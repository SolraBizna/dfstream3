#define _BSD_SOURCE
#define _POSIX_SOURCE
#include "SDL.h"
#include <dlfcn.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <errno.h>
#include <pth.h>
#include <assert.h>
#include <time.h>
#include <zlib.h>
#include <stdlib.h>
#include "tttp_server.h"
#include "tttp_scancodes.h"
#include "lsx.h"

// The queue depth to use if we don't receive a 'Queu' message
#define DEFAULT_QUEUE_DEPTH 5

// Authentication stuff
static const char* master_username = NULL;
static uint8_t master_salt[TTTP_SALT_LENGTH];
static uint8_t guest_salt[TTTP_SALT_LENGTH];
static uint8_t master_verifier[TTTP_VERIFIER_LENGTH];
static uint8_t guest_verifier[TTTP_VERIFIER_LENGTH];
static uint8_t fake_verifier_generator[SHA256_HASHBYTES];
static uint8_t public_key[TTTP_PUBLIC_KEY_LENGTH];
static uint8_t private_key[TTTP_PRIVATE_KEY_LENGTH];

// Our fake display surface
static SDL_Surface* screen = NULL;

// The frame number of the current frame, and of the most recent frame that has
// been sent to at least one master
static Uint64 frame = 0, master_synced_frame = 0;

// Buffers and info for the decoded display
static uint8_t* term_buffer, *term_colors, *term_chars;
static Uint16 cols, rows;

// Most recently requested delay and interval for key repeat
static int kd = 0, ki = 0;

// PTH events used to reduce CPU usage
static pth_event_t masterframe_event, no_first_context_event;

// The PTH thread that handles incoming connections
static pth_t listen_tid;

// The key used to access the libtttp thread-local storage block
static pth_key_t thread_local_key;

// The socket on which we're listening for incoming connections
static int listen_socket = -1;

// Palette stuff
#define PALETTE_MAX 16 // built into the TTTP protocol now
// The palette, as 32-bit pixels
static Uint32 palette_packed[PALETTE_MAX];
// The palette, in the wire format used by TTTP
static Uint8 palette_unpacked[PALETTE_MAX*3];
// The number of currently-active colors in the palette
static int palette_count = 0;

// A "tttpcontext" struct contains all the state information associated with a
// given TTTP connection.
struct tttpcontext {
  // The PTH thread corresponding to this connection
  pth_t tid;
  // The libtttp context for this connection
  tttp_server* tttp;
  // The socket for this connection
  int sock;
  // The number of open queue slots for frames
  int queued_frames;
  // The number of occupied queue slots for frames
  int inflight_frames;
  // The values for repeat delay and interval that are active
  int synced_kd, synced_ki;
  // The modifier keys currently active
  SDLMod cur_mods;
  // The X and Y location of the mouse
  int cur_mouse_x, cur_mouse_y;
  // The mouse buttons currently active
  Uint8 cur_mouse_buttons;
  // 0 if this is a guest connection, 1 if it's a master connection,
  // -1 if it's an incomplete connection with a wrong username
  int8_t is_master;
  // The number of colors that were in the palette last time we sent a frame
  // (if it has changed, we know we need to send a new palette)
  int8_t synced_palette_count;
  // 0 if the connection is handshaking, 1 if it's complete
  // (used to decide whether we should interrupt a read to post a frame)
  int8_t in_main_loop;
  // A PTH event ring containing an event that triggers if a new frame becomes
  // available
  pth_event_t newframe_event;
  // The frame number of the last frame that was queued
  Uint64 synced_frame;
  // A ring buffer that contains the data to be sent over this connection
  uint32_t sendbuf_head, sendbuf_tail;
  uint8_t sendbuf[1024];
  // tttpcontexts are members of a doubly-linked list
  struct tttpcontext* next;
  struct tttpcontext* prev;
};

// The anchor for the list of active contexts
static struct tttpcontext* first_context = NULL;

// The libtttp callback to flush all buffered data on this connection
static void flush_data(void* _data) {
  struct tttpcontext* this = (struct tttpcontext*)_data;
  if(this->sock < 0) return;
  while(this->sendbuf_head > this->sendbuf_tail) {
    ssize_t did = pth_write(this->sock, this->sendbuf + this->sendbuf_tail,
                            this->sendbuf_head - this->sendbuf_tail);
    if(did <= 0) {
      if(errno == EAGAIN)
        continue;
      else {
        close(this->sock);
        this->sock = -1;
        return;
      }
    }
    else
      this->sendbuf_tail += did;
  }
  this->sendbuf_tail = this->sendbuf_head = 0;  
}

// The libtttp callback to send some data over this connection
static int send_data(void* _data, const void* buf, size_t bufsz) {
  struct tttpcontext* this = (struct tttpcontext*)_data;
  if(this->sock < 0) return -1;
  if(this->sendbuf_head >= sizeof(this->sendbuf)) flush_data(_data);
  if(this->sock < 0) return -1;
  if(this->sendbuf_head + bufsz <= sizeof(this->sendbuf)) {
    memcpy(this->sendbuf + this->sendbuf_head, buf, bufsz);
    this->sendbuf_head += bufsz;
    return 0;
  }
  else {
    while(this->sendbuf_head) {
      flush_data(_data);
      if(this->sock < 0) return -1;
    }
    while(bufsz > 0) {
      ssize_t did = pth_write(this->sock, buf, bufsz);
      if(did <= 0) {
        if(errno == EAGAIN)
          continue;
        else {
          close(this->sock);
          this->sock = -1;
          return -1;
        }
      }
      else {
        buf = ((const uint8_t*)buf) + did;
        bufsz -= did;
      }
    }
  }
}

// The libtttp callback to receive data over this connection
static int recv_data(void* _data, void* buf, size_t bufsz) {
  struct tttpcontext* this = (struct tttpcontext*)_data;
  if(this->sock < 0) return -1;
  ssize_t did = pth_read_ev(this->sock, buf, bufsz,
                            this->in_main_loop ? this->newframe_event : NULL);
  if(did <= 0) {
    if(errno == EAGAIN && did != 0)
      return 0;
    else if(errno == EINTR)
      return 0; // newframe!
    else {
      close(this->sock);
      this->sock = -1;
      return -1;
    }
  }
  else return did;
}

// The libtttp callback used when an unrecoverable error occurs
static void fatal_error(void* _data, const char* why) {
  fprintf(stderr, "libtttp fatal error: %s\n", why);
  fflush(stderr);
  abort();
}

// Used to create a PTH event that triggers when a new frame is posted AND this
// client has a frame queued
static int wait_until_new_frame(void* _data) {
  struct tttpcontext* this = (struct tttpcontext*)_data;
  return this->queued_frames > 0 && this->synced_frame != frame;
}

// A currently-unused debug function that dumps the context list
static void print_contexts() {
  int n = 0;
  fprintf(stderr, "Starting at first_context\n");
  for(struct tttpcontext* p = first_context; p; p = p->next) {
    if(++n > 10) {
      fprintf(stderr, "...\n");
      break;
    }
    fprintf(stderr, "%p <- %p(%p) -> %p\n", p->prev, p, p->tid, p->next);
  }
  fflush(stderr);
}

// (forward declaration for newcontext's benefit)
static void* client_thread(struct tttpcontext* this);
// Creates a new tttpcontext for a new incoming connection. This includes
// spawning the PTH thread for that context.
// The context must later be destroyed with deletecontext.
static struct tttpcontext* newcontext(int sock) {
  struct tttpcontext* new = malloc(sizeof(struct tttpcontext));
  new->sock = sock;
  new->tttp = tttp_server_init(new,
                               recv_data,
                               send_data,
                               flush_data,
                               fatal_error,
                               NULL);
  new->next = first_context;
  new->prev = NULL;
  new->queued_frames = DEFAULT_QUEUE_DEPTH;
  new->sendbuf_head = 0;
  new->sendbuf_tail = 0;
  new->inflight_frames = 0;
  new->is_master = 0;
  new->synced_frame = 0;
  new->synced_kd = 0;
  new->synced_ki = 0;
  new->synced_palette_count = 0;
  new->in_main_loop = 0;
  new->cur_mods = 0;
  new->cur_mouse_buttons = 0;
  new->cur_mouse_x = 0;
  new->cur_mouse_y = 0;
  new->newframe_event = pth_event(PTH_EVENT_FUNC, wait_until_new_frame,
                                  new, pth_time(0, 0));
  new->tid = pth_spawn(NULL, (void*(*)(void*))client_thread, new);
  if(first_context) first_context->prev = new;
  first_context = new;
  //print_contexts();
  return new;
}
// forward declarations for deletecontext's benefit
static void handle_Kbtn(void*, int, uint16_t);
static void handle_Mbtn(void* _data, int pressed, uint16_t button);
// Cleans up the state for a given context. If its thread is still running,
// remedies that situation. If its thread is the running thread, this cleanly
// ends the thread's execution.
static void deletecontext(struct tttpcontext* ctx) {
  // Any modifiers that were held, explicitly release.
  if(ctx->cur_mods & KMOD_LSHIFT) handle_Kbtn(ctx, 0, KEY_LEFT_SHIFT);
  if(ctx->cur_mods & KMOD_RSHIFT) handle_Kbtn(ctx, 0, KEY_RIGHT_SHIFT);
  if(ctx->cur_mods & KMOD_LCTRL) handle_Kbtn(ctx, 0, KEY_LEFT_CONTROL);
  if(ctx->cur_mods & KMOD_RCTRL) handle_Kbtn(ctx, 0, KEY_RIGHT_CONTROL);
  if(ctx->cur_mods & KMOD_LALT) handle_Kbtn(ctx, 0, KEY_LEFT_ALT);
  if(ctx->cur_mods & KMOD_RALT) handle_Kbtn(ctx, 0, KEY_RIGHT_ALT);
  if(ctx->cur_mods & KMOD_LMETA) handle_Kbtn(ctx, 0, KEY_LEFT_GUI);
  if(ctx->cur_mods & KMOD_RMETA) handle_Kbtn(ctx, 0, KEY_RIGHT_GUI);
  if(ctx->cur_mods & KMOD_NUM) handle_Kbtn(ctx, 0, KEY_NUM_LOCK);
  if(ctx->cur_mods & KMOD_CAPS) handle_Kbtn(ctx, 0, KEY_CAPS_LOCK);
  // Likewise any mouse buttons.
  if(ctx->cur_mouse_buttons & SDL_BUTTON_LMASK)
    handle_Mbtn(ctx, 0, TTTP_LEFT_MOUSE_BUTTON);
  if(ctx->cur_mouse_buttons & SDL_BUTTON_MMASK)
    handle_Mbtn(ctx, 0, TTTP_MIDDLE_MOUSE_BUTTON);
  if(ctx->cur_mouse_buttons & SDL_BUTTON_RMASK)
    handle_Mbtn(ctx, 0, TTTP_RIGHT_MOUSE_BUTTON);
  if(ctx->cur_mouse_buttons & SDL_BUTTON_X1)
    handle_Mbtn(ctx, 0, TTTP_EXTENDED_MOUSE_BUTTON(0));
  if(ctx->cur_mouse_buttons & SDL_BUTTON_X2)
    handle_Mbtn(ctx, 0, TTTP_EXTENDED_MOUSE_BUTTON(1));
  // Make sure any outstanding data gets sent out, if possible, then close the
  // socket.
  flush_data(ctx);
  close(ctx->sock);
  // Clean up the libtttp context.
  tttp_server_fini(ctx->tttp);
  // Remove ourselves from the context list, as we are no longer valid.
  if(ctx->next) ctx->next->prev = ctx->prev;
  if(ctx->prev) ctx->prev->next = ctx->next;
  else if(ctx == first_context) first_context = ctx->next;
  else
    fprintf(stderr, "orphaned context? incoming double free...\n");
  // Free our PTH event ring
  pth_event_free(ctx->newframe_event, PTH_FREE_ALL);
  // and now, final cleanup... terminate the thread, free the memory
  pth_t tid = ctx->tid;
  free(ctx);
  if(tid != pth_self()) {
    //fprintf(stderr, "cancel other, call pth_abort\n");
    pth_abort(tid);
  }
  else {
    //fprintf(stderr, "cancel self, call pth_exit\n");
    pth_exit(NULL);
  }
}

// Used to create a PTH event that triggers when at least one master has caught
// up with display
static int wait_until_master_in_sync(void* unused) {
  (void)unused;
  return master_synced_frame == frame;
}

// Used to create a PTH event that triggers when there are no active contexts
// anymore (so we can use a raw, blocking "accept" and not waste CPU when there
// is nobody watching)
static int wait_until_no_first_context(void* unused) {
  (void)unused;
  return first_context == NULL;
}

// Takes a raw 32-bit pixel and returns its color in the palette. If it wasn't
// found in the palette, inserts it and returns that value.
static Uint8 getcolor(Uint32 c) {
  int top = palette_count, bot = 0;
  while(top > bot) {
    int mid = (top + bot) >> 1;
    if(palette_packed[mid] > c)
      top = mid;
    else if(palette_packed[mid] < c)
      bot = mid + 1;
    else
      return mid;
  }
  if(top >= PALETTE_MAX) {
    fprintf(stderr, "WARNING: COLOR OVERRUN FROM %06X, WILL SPAM THIS MESSAGE UNTIL YOU FIX IT\n", c);
    return PALETTE_MAX-1;
  }
  if(top < palette_count) {
    memmove(palette_packed + top + 1, palette_packed + top, (palette_count - top) * sizeof(*palette_packed));
    memmove(palette_unpacked + (top + 1) * 3, palette_unpacked + top * 3, (palette_count - top) * 3);
  }
  palette_packed[top] = c;
  palette_unpacked[top*3] = c >> 16;
  palette_unpacked[top*3+1] = c >> 8;
  palette_unpacked[top*3+2] = c;
  ++palette_count;
  return top;
}

// The worker function that handles incoming connections
static void* listen_thread(void* _) {
  (void)_;
  while(1) {
    int peer_socket;
    // If at least one person is watching us, we use the PTH function; it will
    // block this "thread" until someone connects, OR the last person
    // disconnects.
    // If nobody is watching us, we use the raw function; it will effectively
    // block the process until somebody connects, thus avoiding wasting CPU on
    // stuff nobody will see.
    if(first_context) peer_socket = pth_accept_ev(listen_socket, NULL, NULL, no_first_context_event);
    else peer_socket = accept(listen_socket, NULL, NULL);
    if(peer_socket >= 0) {
      int one = 1;
      // Disable Nagle's algorithm on this socket. We manage our own buffer.
      setsockopt(peer_socket, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
      newcontext(peer_socket);
    }
    else pth_yield(NULL);
  }
}

// This function is required by libtttp, so it can have a thread-local storage
// block, so it can handle GMP errors in a sane manner
tttp_thread_local_block* tttp_get_thread_local_block() {
  void* ret = pth_key_getdata(thread_local_key);
  if(!ret) {
    ret = malloc(sizeof(tttp_thread_local_block));
    pth_key_setdata(thread_local_key, ret);
  }
  return (tttp_thread_local_block*)ret;
}

// This function is called at least once per Flip. Its job is to perform
// initialization as needed. It fully replaces the old constructor.
static void init() {
  if(master_username == NULL) {
    tttp_init();
    master_username = getenv("DFSTREAM3_MASTER_USERNAME");
    const char* master_password_env = getenv("DFSTREAM3_MASTER_PASSWORD");
    const char* master_verifier_env = getenv("DFSTREAM3_MASTER_VERIFIER");
    const char* master_salt_env = getenv("DFSTREAM3_MASTER_SALT");
    if(!master_username || !(master_password_env || (master_verifier_env&&master_salt_env))) {
      fprintf(stderr, "Please set the environment variables DFSTREAM3_MASTER_USERNAME and either DFSTREAM3_MASTER_PASSWORD (not recommended) or DFSTREAM3_MASTER_VERIFIER and DFSTREAM3_MASTER_SALT(recommended).\n");
      fflush(stderr);
      abort();
    }
    if(master_password_env && master_verifier_env && master_salt_env)
      fprintf(stderr, "DFSTREAM3_MASTER_PASSWORD and DFSTREAM3_MASTER_VERIFIER+_SALT both exist, will use the verifier\n");
    if(master_verifier_env && master_salt_env) {
      if(!tttp_key_from_base64(master_verifier_env, master_verifier)) {
        fprintf(stderr, "DFSTREAM3_MASTER_VERIFIER did not contain a valid verifier!\n");
        fflush(stderr);
        abort();
      }
      if(!tttp_salt_from_base64(master_salt_env, master_salt)) {
        fprintf(stderr, "DFSTREAM3_MASTER_VERIFIER did not contain a valid verifier!\n");
        fflush(stderr);
        abort();
      }
      lsx_calculate_sha256(master_verifier, sizeof(master_verifier),
                           fake_verifier_generator);
    }
    else {
      assert(master_password_env);
      lsx_get_random(fake_verifier_generator, sizeof(fake_verifier_generator));
      lsx_get_random(master_salt, sizeof(master_salt));
      size_t master_password_len = strlen(master_password_env);
      tttp_password_to_verifier(NULL, NULL,
                                master_password_env, master_password_len,
                                master_salt, master_verifier);
    }
    lsx_calculate_sha256(fake_verifier_generator,
                         sizeof(fake_verifier_generator),
                         guest_salt);
    tttp_password_to_verifier(NULL, NULL,
                              "", 0, guest_salt, guest_verifier);
    FILE* f = fopen("tttp_private_key.utxt", "r");
    if(f) {
      char buf[1024]; // should be more than enough
      size_t red = fread(buf, 1, sizeof(buf), f);
      if(red >= 1024)
        fprintf(stderr, "Got bored reading the private key, it might have cut off\n");
      if(!tttp_key_from_base64(buf, private_key)
         || !tttp_generate_public_key(NULL, NULL, private_key, public_key)) {
        fprintf(stderr, "tttp_private_key.utxt didn't contain a valid private key, put a valid one in or remove it\n");
        fflush(stderr);
        abort();
      }
      fclose(f);
    }
    else {
      fprintf(stderr, "Generating a private key...");
      do {
        lsx_get_random(private_key, sizeof(private_key));
      } while(!tttp_generate_public_key(NULL, NULL, private_key, public_key));
      fprintf(stderr, "Done.\n");
      f = fopen("tttp_private_key.utxt", "w");
      if(f) {
        char keybuf[TTTP_KEY_BASE64_BUFFER_SIZE];
        tttp_key_to_base64(private_key, keybuf);
        fputs(keybuf, f);
        fclose(f);
      }
      else {
        fprintf(stderr, "Couldn't save private key (%s while opening tttp_private_key.utxt)\n", strerror(errno));
        fprintf(stderr, "This will screw future clients, so I'm aborting\n");
        fflush(stderr);
        abort();
      }
      f = fopen("tttp_public_key.utxt", "w");
      if(f) {
        char keybuf[TTTP_KEY_BASE64_BUFFER_SIZE];
        tttp_key_to_base64(public_key, keybuf);
        fprintf(f, "(This file is NOT read by dfstream. This is for your reference only. This file is overwritten every time dfstream initializes.)\n\n");
        fputs(keybuf, f);
        fputs("\nKey fingerprint: ", f);
        tttp_get_key_fingerprint(public_key, keybuf);
        fputs(keybuf, f);
        fclose(f);
      }
      else
        fprintf(stderr, "Couldn't save public key, that's inconvenient\n");
    }
  }
  if(listen_socket < 0) {
    if(!pth_init()) abort();
    if(!pth_key_create(&thread_local_key, free)) abort();
    masterframe_event = pth_event(PTH_EVENT_FUNC, wait_until_master_in_sync,
                                  NULL, pth_time(0, 0));
    no_first_context_event = pth_event(PTH_EVENT_FUNC,
                                       wait_until_no_first_context,
                                       NULL, pth_time(0, 0));
    struct sockaddr_in addr;
    listen_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(listen_socket < 0) {
      perror("Unable to create listen socket");
      fflush(stderr);
      abort();
    }
    addr.sin_family = AF_INET;
    const char* portstr = getenv("DFSTREAM3_PORT");
    addr.sin_port = htons(7028);
    if(portstr && *portstr) {
      char* e;
      unsigned long l = strtoul(portstr, &e, 0);
      if(!*e) {
	if(l < 1024 || l >= 49152)
	  fprintf(stderr, "port must be >= 1024 and < 49152\nusing 7028\n");
	else
	  addr.sin_port = htons(l);
      }
      else
	fprintf(stderr, "invalid port given, using 7028\n");
    }
    addr.sin_addr.s_addr = INADDR_ANY;
  rego:
    if(bind(listen_socket, (struct sockaddr*)&addr, sizeof(struct sockaddr_in))) {
      if(errno == EADDRINUSE) {
	fprintf(stderr, "*:%i in use, will retry in 10 seconds...\n", ntohs(addr.sin_port));
        fflush(stderr);
	usleep(10000000);
	goto rego;
      }
      perror("bind");
      fflush(stderr);
      abort();
    }
    fprintf(stderr, "dfstream3 ready for incoming connection, port %i.\n", ntohs(addr.sin_port));
    fflush(stderr);
    if(listen(listen_socket,3)) {
      perror("listen");
      fflush(stderr);
      abort();
    }
    listen_tid = pth_spawn(NULL, listen_thread, NULL);
  }
}

// The flagfilter callback for libtttp. The only flag we support is encryption.
static uint32_t flagfilter(uint32_t inflags) {
  return inflags & TTTP_FLAG_ENCRYPTION;
}

// Called whenever the client acknowledges receiving a frame;
static void handle_ONES(void* _data) {
  struct tttpcontext* this = (struct tttpcontext*)_data;
  // If we knew we had sent this client a frame, we queue another one.
  if(this->inflight_frames > 0) {
    --this->inflight_frames;
    ++this->queued_frames;
  }
}

// Called when the client requests a specific queue depth. To the degree
// possible, we honor this.
static void handle_Queu(void* _data, uint8_t new_depth) {
  struct tttpcontext* this = (struct tttpcontext*)_data;
  if(!new_depth) new_depth = DEFAULT_QUEUE_DEPTH;
  this->queued_frames = new_depth - this->inflight_frames;
}

// Called when the client presses or releases a key.
static void handle_Kbtn(void* _data, int pressed, uint16_t scancode) {
  struct tttpcontext* this = (struct tttpcontext*)_data;
  // Only masters may press keys.
  if(!this->is_master) return;
  SDL_Event evt;
  // Control-9 is a special key combination that kills Dwarf Fortress, in case
  // of game-breaking bugs or (some) hangs.
  if((this->cur_mods & KMOD_CTRL) && scancode == KEY_9)
    kill(getpid(), SIGKILL);
  // Simulate a KEYDOWN or KEYUP event appropriately
  evt.type = pressed ? SDL_KEYDOWN : SDL_KEYUP;
  evt.key.keysym.mod = this->cur_mods;
  evt.key.keysym.scancode = 0;
  evt.key.keysym.unicode = 0;
  if(scancode < 128) {
    // ASCII keycodes!
    // Many SDLK_* values are just the corresponding ASCII value. This maps
    // nicely onto TTTP scancodes, with a few exceptions.
    // SDL uses the carriage return value where TTTP uses the line feed
    if(scancode == KEY_ENTER)
      evt.key.keysym.sym = SDLK_RETURN;
    // SDL uses lowercase letters where TTTP uses capital ones
    else if(scancode >= 'A' && scancode <= 'Z')
      evt.key.keysym.sym = scancode + 32;
    // All other values map directly
    else
      evt.key.keysym.sym = scancode;
  }
  else {
    // We must manually map any non-ASCII scancodes to their SDL equivalents.
    // I'm pretty sure this list is complete, at least in terms of keys that
    // matter in DF.
    switch(scancode) {
    case KEY_F1: evt.key.keysym.sym = SDLK_F1; break;
    case KEY_F2: evt.key.keysym.sym = SDLK_F2; break;
    case KEY_F3: evt.key.keysym.sym = SDLK_F3; break;
    case KEY_F4: evt.key.keysym.sym = SDLK_F4; break;
    case KEY_F5: evt.key.keysym.sym = SDLK_F5; break;
    case KEY_F6: evt.key.keysym.sym = SDLK_F6; break;
    case KEY_F7: evt.key.keysym.sym = SDLK_F7; break;
    case KEY_F8: evt.key.keysym.sym = SDLK_F8; break;
    case KEY_F9: evt.key.keysym.sym = SDLK_F9; break;
    case KEY_F10: evt.key.keysym.sym = SDLK_F10; break;
    case KEY_F11: evt.key.keysym.sym = SDLK_F11; break;
    case KEY_F12: evt.key.keysym.sym = SDLK_F12; break;
    case KEY_SYSREQ: evt.key.keysym.sym = SDLK_SYSREQ; break;
    case KEY_HOME: evt.key.keysym.sym = SDLK_HOME; break;
    case KEY_END: evt.key.keysym.sym = SDLK_END; break;
    case KEY_UP: evt.key.keysym.sym = SDLK_UP; break;
    case KEY_DOWN: evt.key.keysym.sym = SDLK_DOWN; break;
    case KEY_LEFT: evt.key.keysym.sym = SDLK_LEFT; break;
    case KEY_RIGHT: evt.key.keysym.sym = SDLK_RIGHT; break;
    case KEY_PAGE_UP: evt.key.keysym.sym = SDLK_PAGEUP; break;
    case KEY_PAGE_DOWN: evt.key.keysym.sym = SDLK_PAGEDOWN; break;
    case KEY_KEYPAD_0: evt.key.keysym.sym = SDLK_KP0; break;
    case KEY_KEYPAD_1: evt.key.keysym.sym = SDLK_KP1; break;
    case KEY_KEYPAD_2: evt.key.keysym.sym = SDLK_KP2; break;
    case KEY_KEYPAD_3: evt.key.keysym.sym = SDLK_KP3; break;
    case KEY_KEYPAD_4: evt.key.keysym.sym = SDLK_KP4; break;
    case KEY_KEYPAD_5: evt.key.keysym.sym = SDLK_KP5; break;
    case KEY_KEYPAD_6: evt.key.keysym.sym = SDLK_KP6; break;
    case KEY_KEYPAD_7: evt.key.keysym.sym = SDLK_KP7; break;
    case KEY_KEYPAD_8: evt.key.keysym.sym = SDLK_KP8; break;
    case KEY_KEYPAD_9: evt.key.keysym.sym = SDLK_KP9; break;
    case KEY_KEYPAD_PERIOD: evt.key.keysym.sym = SDLK_KP_PERIOD; break;
    case KEY_KEYPAD_SLASH: evt.key.keysym.sym = SDLK_KP_DIVIDE; break;
    case KEY_KEYPAD_ASTERISK: evt.key.keysym.sym = SDLK_KP_MULTIPLY; break;
    case KEY_KEYPAD_HYPHEN: evt.key.keysym.sym = SDLK_KP_MINUS; break;
    case KEY_KEYPAD_PLUS: evt.key.keysym.sym = SDLK_KP_PLUS; break;
    case KEY_KEYPAD_ENTER: evt.key.keysym.sym = SDLK_KP_ENTER; break;
    case KEY_KEYPAD_EQUAL_SIGN:
    case KEY_KEYPAD_EQUAL: evt.key.keysym.sym = SDLK_KP_EQUALS; break;
    case KEY_LEFT_CONTROL:
      if(pressed) this->cur_mods |= KMOD_LCTRL;
      else this->cur_mods &= ~KMOD_LCTRL;
      evt.key.keysym.sym = SDLK_LCTRL;
      break;
    case KEY_RIGHT_CONTROL:
      if(pressed) this->cur_mods |= KMOD_RCTRL;
      else this->cur_mods &= ~KMOD_RCTRL;
      evt.key.keysym.sym = SDLK_RCTRL;
      break;
    case KEY_LEFT_SHIFT:
      if(pressed) this->cur_mods |= KMOD_LSHIFT;
      else this->cur_mods &= ~KMOD_LSHIFT;
      evt.key.keysym.sym = SDLK_LSHIFT;
      break;
    case KEY_RIGHT_SHIFT:
      if(pressed) this->cur_mods |= KMOD_RSHIFT;
      else this->cur_mods &= ~KMOD_RSHIFT;
      evt.key.keysym.sym = SDLK_RSHIFT;
      break;
    case KEY_LEFT_ALT:
      if(pressed) this->cur_mods |= KMOD_LALT;
      else this->cur_mods &= ~KMOD_LALT;
      evt.key.keysym.sym = SDLK_LALT;
      break;
    case KEY_RIGHT_ALT:
      if(pressed) this->cur_mods |= KMOD_RALT;
      else this->cur_mods &= ~KMOD_RALT;
      evt.key.keysym.sym = SDLK_RALT;
      break;
    case KEY_LEFT_GUI:
      if(pressed) this->cur_mods |= KMOD_LMETA;
      else this->cur_mods &= ~KMOD_LMETA;
      evt.key.keysym.sym = SDLK_LSUPER;
      break;
    case KEY_RIGHT_GUI:
      if(pressed) this->cur_mods |= KMOD_RMETA;
      else this->cur_mods &= ~KMOD_RMETA;
      evt.key.keysym.sym = SDLK_RSUPER;
      break;
    case KEY_NUM_LOCK:
      if(pressed) this->cur_mods |= KMOD_NUM;
      else this->cur_mods &= ~KMOD_NUM;
      evt.key.keysym.sym = SDLK_NUMLOCK;
      break;
    case KEY_CAPS_LOCK:
      if(pressed) this->cur_mods |= KMOD_CAPS;
      else this->cur_mods &= ~KMOD_CAPS;
      evt.key.keysym.sym = SDLK_CAPSLOCK;
      break;
    default:
      // TTTP supports many scancodes that have no analogs in SDL 1.2. We
      // "support" them by sending a keyboard event with a zero "sym" and
      // nonzero scancode. I don't think DF can use these, but...
      evt.key.keysym.scancode = scancode - 128;
      evt.key.keysym.sym = 0;
    }
  }
  if(SDL_PeepEvents(&evt, 1, SDL_ADDEVENT, 0)!=1) fprintf(stderr, "%s\n", SDL_GetError());
}

// A table mapping CP437 codepoints to Unicode ones. Unicode codepoints can't
// all fit in 16 bits... but we use 16 because:
// - All CP437 codepoints are mapped to Unicode code points in the BMP (i.e.
// ones that fit in 16 bits)
// - SDL 1.2 only supports 16 bit codepoints anyway
static const uint16_t codepoint_table[256] = {
  0x0000, 0x263a, 0x263b, 0x2665, 0x2666, 0x2663, 0x2660, 0x2022,
  0x25d8, 0x25cb, 0x25d9, 0x2642, 0x2640, 0x266a, 0x266b, 0x263c,
  0x25ba, 0x25c4, 0x2195, 0x203c, 0x00b6, 0x00a7, 0x25ac, 0x21a8,
  0x2191, 0x2193, 0x2192, 0x2190, 0x221f, 0x2194, 0x25b2, 0x25bc,
  0x0020, 0x0021, 0x0022, 0x0023, 0x0024, 0x0025, 0x0026, 0x0027,
  0x0028, 0x0029, 0x002a, 0x002b, 0x002c, 0x002d, 0x002e, 0x002f,
  0x0030, 0x0031, 0x0032, 0x0033, 0x0034, 0x0035, 0x0036, 0x0037,
  0x0038, 0x0039, 0x003a, 0x003b, 0x003c, 0x003d, 0x003e, 0x003f,
  0x0040, 0x0041, 0x0042, 0x0043, 0x0044, 0x0045, 0x0046, 0x0047,
  0x0048, 0x0049, 0x004a, 0x004b, 0x004c, 0x004d, 0x004e, 0x004f,
  0x0050, 0x0051, 0x0052, 0x0053, 0x0054, 0x0055, 0x0056, 0x0057,
  0x0058, 0x0059, 0x005a, 0x005b, 0x005c, 0x005d, 0x005e, 0x005f,
  0x0060, 0x0061, 0x0062, 0x0063, 0x0064, 0x0065, 0x0066, 0x0067,
  0x0068, 0x0069, 0x006a, 0x006b, 0x006c, 0x006d, 0x006e, 0x006f,
  0x0070, 0x0071, 0x0072, 0x0073, 0x0074, 0x0075, 0x0076, 0x0077,
  0x0078, 0x0079, 0x007a, 0x007b, 0x007c, 0x007d, 0x007e, 0x007f,
  0x00c7, 0x00fc, 0x00e9, 0x00e2, 0x00e4, 0x00e0, 0x00e5, 0x00e7,
  0x00ea, 0x00eb, 0x00e8, 0x00ef, 0x00ee, 0x00ec, 0x00c4, 0x00c5,
  0x00c9, 0x00e6, 0x00c6, 0x00f4, 0x00f6, 0x00f2, 0x00fb, 0x00f9,
  0x00ff, 0x00d6, 0x00dc, 0x00a2, 0x00a3, 0x00a5, 0x20a7, 0x0192,
  0x00e1, 0x00ed, 0x00f3, 0x00fa, 0x00f1, 0x00d1, 0x00aa, 0x00ba,
  0x00bf, 0x2310, 0x00ac, 0x00bd, 0x00bc, 0x00a1, 0x00ab, 0x00bb,
  0x2591, 0x2592, 0x2593, 0x2502, 0x2524, 0x2561, 0x2562, 0x2556,
  0x2555, 0x2563, 0x2551, 0x2557, 0x255d, 0x255c, 0x255b, 0x2510,
  0x2514, 0x2534, 0x252c, 0x251c, 0x2500, 0x253c, 0x255e, 0x255f,
  0x255a, 0x2554, 0x2569, 0x2566, 0x2560, 0x2550, 0x256c, 0x2567,
  0x2568, 0x2564, 0x2565, 0x2559, 0x2558, 0x2552, 0x2553, 0x256b,
  0x256a, 0x2518, 0x250c, 0x2588, 0x2584, 0x258c, 0x2590, 0x2580,
  0x03b1, 0x00df, 0x0393, 0x03c0, 0x03a3, 0x03c3, 0x00b5, 0x03c4,
  0x03a6, 0x0398, 0x03a9, 0x03b4, 0x221e, 0x03c6, 0x03b5, 0x2229,
  0x2261, 0x00b1, 0x2265, 0x2264, 0x2320, 0x2321, 0x00f7, 0x2248,
  0x00b0, 0x2219, 0x00b7, 0x221a, 0x207f, 0x00b2, 0x25a0, 0x00a0,
};

// Called when the client sends textual input.
static void handle_Text(void* _data, const uint8_t* text, size_t len) {
  struct tttpcontext* this = (struct tttpcontext*)_data;
  // Only masters may type!
  if(!this->is_master) return;
  // We simulate a keydown event (no corresponding keyup) with a zero sym and
  // scancode, for each character typed.
  SDL_Event evt;
  evt.type = SDL_KEYDOWN;
  evt.key.keysym.mod = this->cur_mods;
  evt.key.keysym.sym = 0;
  evt.key.keysym.scancode = 0;
  // We don't use libtttp in Unicode mode, so the text is in CP437. Translation
  // to Unicode is trivial.
  for(const uint8_t* p = text; p < text + len; ++p) {
    evt.key.keysym.unicode = codepoint_table[*p];
    if(SDL_PeepEvents(&evt, 1, SDL_ADDEVENT, 0)!=1) fprintf(stderr, "%s\n", SDL_GetError());
  }
}

// Called when the client moves the mouse.
static void handle_Mous(void* _data, int16_t x, int16_t y) {
  struct tttpcontext* this = (struct tttpcontext*)_data;
  // Only masters may mouse!
  if(!this->is_master) return;
  // TODO: highlights
  // We simulate a MOUSEMOTION event appropriately.
  SDL_Event evt;
  evt.type = SDL_MOUSEMOTION;
  evt.motion.state = this->cur_mouse_buttons;
  // One bitfont cell is 10 pixels wide, but TTTP gives us mouse coordinates in
  // character cells
  evt.motion.x = x * 10;
  evt.motion.y = y;
  evt.motion.xrel = x * 10 - this->cur_mouse_x;
  evt.motion.yrel = y - this->cur_mouse_y;
  this->cur_mouse_x = x * 10;
  this->cur_mouse_y = y;
  if(SDL_PeepEvents(&evt, 1, SDL_ADDEVENT, 0)!=1) fprintf(stderr, "%s\n", SDL_GetError());
}

static void handle_Mbtn(void* _data, int pressed, uint16_t button) {
  struct tttpcontext* this = (struct tttpcontext*)_data;
  // ONLY MASTERS MAY MOUSE!
  if(!this->is_master) return;
  // TODO: highlights
  // We simulate a MOUSEBUTTONDOWN or MOUSEBUTTONUP event.
  SDL_Event evt;
  // Map TTTP button indices to SDL button indices
  switch(button) {
  case TTTP_LEFT_MOUSE_BUTTON:
    evt.button.button = SDL_BUTTON_LEFT;
    break;
  case TTTP_MIDDLE_MOUSE_BUTTON:
    evt.button.button = SDL_BUTTON_MIDDLE;
    break;
  case TTTP_RIGHT_MOUSE_BUTTON:
    evt.button.button = SDL_BUTTON_RIGHT;
    break;
  case TTTP_EXTENDED_MOUSE_BUTTON(0):
    evt.button.button = SDL_BUTTON_X1;
    break;
  case TTTP_EXTENDED_MOUSE_BUTTON(1):
    evt.button.button = SDL_BUTTON_X2;
    break;
  default: return; // unsupported button
  }
  evt.type = pressed ? SDL_MOUSEBUTTONDOWN : SDL_MOUSEBUTTONUP;
  evt.button.state = pressed ? SDL_PRESSED : SDL_RELEASED;
  evt.button.x = this->cur_mouse_x;
  evt.button.y = this->cur_mouse_y;
  if(SDL_PeepEvents(&evt, 1, SDL_ADDEVENT, 0)!=1) fprintf(stderr, "%s\n", SDL_GetError());
  // Keep track of pressed mouse buttons for future MOUSEMOTION events
  if(pressed)
    this->cur_mouse_buttons |= SDL_BUTTON(1<<evt.button.button);
  else
    this->cur_mouse_buttons &= ~SDL_BUTTON(1<<evt.button.button);
}

// Called when the client scrolls, with a mousewheel or other scrolling device
static void handle_Scrl(void* _data, int8_t x, int8_t y) {
  struct tttpcontext* this = (struct tttpcontext*)_data;
  // ONLY MASTERS MAY SCROLL! Peasants must use clay tablets.
  if(!this->is_master) return;
  // We only care about Y-axis scrolling. SDL 1.2 has no concept of X-axis
  // scrolling.
  if(y != 0) {
    // We simulate MOUSEBUTTONDOWN and MOUSEBUTTONUP events as appropriate,
    // one for each "tick" of scrolling. We give the up event even though SDL
    // may not do this for real scroll wheels. Why? Because doing things right
    // is worth a few extra lines of code.
    SDL_Event evt;
    evt.button.button = y < 0 ? SDL_BUTTON_WHEELUP : SDL_BUTTON_WHEELDOWN;
    evt.button.x = this->cur_mouse_x;
    evt.button.y = this->cur_mouse_y;
    if(y < 0) y = -y;
    while(y > 0) {
      evt.type = SDL_MOUSEBUTTONDOWN;
      evt.button.state = SDL_PRESSED;
      if(SDL_PeepEvents(&evt, 1, SDL_ADDEVENT, 0)!=1) fprintf(stderr, "%s\n", SDL_GetError());
      --y;
      evt.type = SDL_MOUSEBUTTONUP;
      evt.button.state = SDL_RELEASED;
      if(SDL_PeepEvents(&evt, 1, SDL_ADDEVENT, 0)!=1) fprintf(stderr, "%s\n", SDL_GetError());
    }
  }
}

// The beef! This function handles one client, starting with the handshake and
// proceeding until disconnection.
static void* client_thread(struct tttpcontext* this) {
  // Initial handshake!
  {
    // These variables are only used during the handshake
    tttp_handshake_result res;
    uint8_t* neg_username;
    size_t neg_usernamelen;
    do {
      res = tttp_server_pump_beginning(this->tttp, flagfilter,
                                       private_key, public_key,
                                       "DFStream", 8,
                                       &neg_username, &neg_usernamelen);
      switch(res) {
      case TTTP_HANDSHAKE_REJECTED:
      case TTTP_HANDSHAKE_ERROR:
        deletecontext(this);
        return NULL;
      default: break;
      }
    } while(res != TTTP_HANDSHAKE_ADVANCE);
    if(neg_username == NULL) {
      // Authentication is not being used. We accept that. This connection is
      // only allowed to spectate.
      this->is_master = 0;
      tttp_server_accept_no_auth(this->tttp);
    }
    else {
      // Authentication is being used. This gets hairy...
      uint8_t valid_verifier[TTTP_VERIFIER_LENGTH];
      uint8_t valid_salt[TTTP_SALT_LENGTH];
      if(!strcmp((const char*)neg_username, master_username)) {
        // They're connecting under master's username
        memcpy(valid_verifier, master_verifier, TTTP_VERIFIER_LENGTH);
        memcpy(valid_salt, master_salt, TTTP_SALT_LENGTH);
        this->is_master = 1;
      }
      else if(neg_usernamelen == 0) {
        // They're connecting with a blank username
        memcpy(valid_verifier, guest_verifier, TTTP_VERIFIER_LENGTH);
        memcpy(valid_salt, guest_salt, TTTP_SALT_LENGTH);
        this->is_master = 0;
      }
      else {
        // They're connecting with another username... reject!
        this->is_master = -1;
        lsx_sha256_context sha256;
        lsx_setup_sha256(&sha256);
        lsx_input_sha256(&sha256, fake_verifier_generator,
                         sizeof(fake_verifier_generator));
        lsx_input_sha256(&sha256, neg_username, neg_usernamelen);
        lsx_finish_sha256(&sha256, valid_salt);
        lsx_destroy_sha256(&sha256);
        // valid_verifier is uninitialized, intentionally; its contents will
        // not change what code path gets executed down the line
      }
      tttp_server_begin_auth(this->tttp, valid_salt, valid_verifier);
      do {
        res = tttp_server_pump_auth(this->tttp);
        switch(res) {
        case TTTP_HANDSHAKE_ERROR:
          deletecontext(this);
          return NULL;
        default: break;
        }
      } while(res != TTTP_HANDSHAKE_ADVANCE && res != TTTP_HANDSHAKE_REJECTED);
      // Yes, this is a bitwise OR. This avoids a branch, which could be used
      // as part of a timing attack.
      if((res == TTTP_HANDSHAKE_REJECTED) | (this->is_master < 0)) {
        fflush(stderr);
        tttp_server_reject_auth(this->tttp);
        deletecontext(this);
        return NULL;
      }
      // If we got this far, the connection was accepted! Tell the client the
      // good news and set up all the callbacks.
      tttp_server_accept_auth(this->tttp);
      tttp_server_set_ones_callback(this->tttp, handle_ONES);
      tttp_server_set_queue_depth_callback(this->tttp, handle_Queu);
      tttp_server_set_key_callback(this->tttp, handle_Kbtn);
      tttp_server_set_text_callback(this->tttp, handle_Text);
      tttp_server_set_mouse_motion_callback(this->tttp, handle_Mous);
      tttp_server_set_mouse_button_callback(this->tttp, handle_Mbtn);
      tttp_server_set_scroll_callback(this->tttp, handle_Scrl);
    }
  }
  // We are now in the main loop.
  this->in_main_loop = 1;
  while(this->sock >= 0) {
    // If we have at least one slot in the queue, and a new frame is available
    if(this->queued_frames > 0 && frame != this->synced_frame) {
      // Send the key repeat message if relevant
      if(this->synced_kd != kd || this->synced_ki != ki) {
        tttp_server_request_key_repeat(this->tttp, kd, ki);
        this->synced_kd = kd;
        this->synced_ki = ki;
      }
      // Send the palette if the client doesn't have ours
      if(this->synced_palette_count != palette_count) {
        tttp_server_send_palette(this->tttp, palette_unpacked, palette_count);
        this->synced_palette_count = palette_count;
      }
      // We set these values here instead of earlier or later because, at this
      // point, we are guaranteed to get far enough to hand the current frame
      // off to libtttp. Hopefully the palette didn't change during a silent
      // send...
      this->synced_frame = frame;
      --this->queued_frames;
      ++this->inflight_frames;
      tttp_server_send_frame(this->tttp, cols, rows, term_buffer);
      // Another thread needs to know when at least one master has sent a given
      // frame
      if(this->is_master && this->synced_frame > master_synced_frame)
        master_synced_frame = this->synced_frame;
    }
    // Do tasks related to this client.
    if(!tttp_server_pump(this->tttp)) break;
  }
  // This thread is over. Its context no longer needs to exist.
  deletecontext(this);
}

// Our fake SetVideoMode function. It sets up a 32-bit-per-pixel surface with
// a known pixel format, and passes it on.
SDL_Surface* SDL_SetVideoMode(int width, int height, int bpp, Uint32 flags) {
  // We don't try to snoop OpenGL modes.
  if(flags & SDL_OPENGL) {
    fprintf(stderr, "Please set PRINT_MODE to 2D in init/init.txt\n");
    fflush(stderr);
    abort();
  }
  // We don't expect Dwarf Fortress to try anything but 32-bpp.
  if(bpp != 32)
    fprintf(stderr, "BPP was %i instead of 32, something might explode\n",bpp);
  // If we already had a display surface, we no longer care about it.
  if(screen) SDL_FreeSurface(screen);
  // Default width and height are 800x60, corresponding to 80x60. If the
  // requested width wasn't a multiple of 10, then either DF is stretching the
  // font or a font other than bitfont was used. Either way, we can't continue.
  if(!width) width = 800;
  else if(width%10) {
    fprintf(stderr, "non-multiple-of-ten-width means wrong font!\n");
    fflush(stderr);
    abort();
  }
  if(!height) height = 60;
  // Create the fake surface to use
  screen = SDL_CreateRGBSurface(0, width, height, 32, 0xFF0000,0xFF00,0xFF,0);
  if(!screen) abort();
  // Set up the buffers to store decoded frames in
  cols = width/10;
  rows = height;
  if(term_buffer) free(term_buffer);
  term_buffer = malloc(cols*rows*2);
  if(!term_buffer) abort();
  term_colors = term_buffer;
  term_chars = term_buffer + cols*rows;
  return screen;
}

// We don't ever give SDL an actual display surface, so we have to intercept
// this call.
SDL_Surface* SDL_DisplayFormat(SDL_Surface* src) {
  return SDL_ConvertSurface(src, screen->format, 0);
}

// The other beef! Called whenever DF is done with a frame.
int SDL_Flip(SDL_Surface* screen) {
  // If no masters have received the last frame, wait until one does...
  if(frame != master_synced_frame)
    pth_wait(masterframe_event);
  // Decode the screen as displayed by DF into characters and colors.
  Uint32* srcp;
 restart: {} // Yuck.
  Uint8* dstcolor = term_colors, *dstchar = term_chars;
  int old_palette_count = palette_count;
  for(Uint16 y = 0; y < rows; ++y) {
    srcp = (Uint32*)((Uint8*)screen->pixels + y * screen->pitch);
    for(Uint16 x = 0; x < cols; ++x) {
      // The first and second pixels of bitfont are always the foreground and
      // background colors.
      Uint8 fg = getcolor(srcp[0]);
      Uint8 bg = getcolor(srcp[1]);
      *dstcolor++ = (fg<<4)|bg;
      // The remaining 8 pixels are the bits of the CP437 code point.
      Uint8 chr = 0;
      if(fg != bg) {
        if(srcp[2] == srcp[0]) chr |= 128;
        if(srcp[3] == srcp[0]) chr |= 64;
        if(srcp[4] == srcp[0]) chr |= 32;
        if(srcp[5] == srcp[0]) chr |= 16;
        if(srcp[6] == srcp[0]) chr |= 8;
        if(srcp[7] == srcp[0]) chr |= 4;
        if(srcp[8] == srcp[0]) chr |= 2;
        if(srcp[9] == srcp[0]) chr |= 1;
      }
      *dstchar++ = chr ? chr : ' ';
      srcp += 10;
    }
  }
  // If the palette count changed, some of the decoded colors are wrong. Do
  // this to avoid one of the two causes of palette flash.
  if(palette_count != old_palette_count) goto restart;
  // We have decoded a new frame, and through the magic of PTH this is all that
  // is needed to notify everyone who was waiting.
  ++frame;
  // Initialize anything that isn't already initialized. We defer proper
  // initialization until the last possible moment to get DF started as fast as
  // possible, in particular if a previous socket on this port is still open
  // and we have to wait for it to close...
  init();
  // Give other threads a chance to run. Any threads that were waiting for a
  // new frame will run, as well as any whose IOs have become available.
  pth_yield(NULL);
  // Our Flip always succeeds.
  return 0;
}

// Give the properties of our simulated mouse instead of any real one SDL
// thinks it has.
Uint8 SDL_GetMouseState(int* x, int* y) {
  struct tttpcontext* p = first_context;
  while(p) {
    if(p->is_master) {
      if(x) *x = p->cur_mouse_x;
      if(y) *y = p->cur_mouse_y;
      return 0;
    }
  }
  if(x) *x = 0;
  if(y) *y = 0;
  return 0;
}

// Keep track of the requested key repeat values, so the client threads can
// distribute them appropriately.
int SDL_EnableKeyRepeat(int delay, int interval) {
  kd = delay;
  ki = interval;
  return 0;
}

// Currently, we don't implement this. A future extension to TTTP might do
// something here.
void SDL_WM_SetCaption(const char* title, const char* icon) {
  return;
}

// Currently, we don't implement this. A future extension to TTTP might do
// something here.
void SDL_WM_SetIcon(SDL_Surface* icon, Uint8* mask) {
  return;
}

// Currently we don't implement a mode where Unicode translation isn't done.
int SDL_EnableUNICODE(int enable) {
  return 1;
}

// Bypass SDL and return our fake video surface.
SDL_Surface* SDL_GetVideoSurface() {
  return screen;
}

// Fake video info function, that tracks our fake display surface, and pretends
// our fake 32-bpp pixel format is the native one for the screen.
static SDL_PixelFormat vf = {NULL,32,4,0,0,0,0,16,8,0,0,255<<16,255<<8,255,0,0,0};
static SDL_VideoInfo vi = {0,0,0,0,0,0,0,0,0,0,0,0,1024,&vf,1024,768};
const SDL_VideoInfo* SDL_GetVideoInfo(void) {
  vi.current_w = cols*10;
  vi.current_h = rows;
  return &vi;
}
