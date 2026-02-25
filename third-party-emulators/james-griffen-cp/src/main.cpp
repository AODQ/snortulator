#include <iostream>
#include <chrono>
#include <thread>
#include "stdint.h"
#include "SDL2/SDL.h"

#define SnortInsert 1

#include <snort-harness/snort-harness.h>
#include <snort-replay/fs.hpp>
#include <snort/snort.h>

#include "imgui.h"

#include "chip8.h"

using namespace std;

// Keypad keymap
uint8_t keymap[16] = {
    SDLK_x,
    SDLK_1,
    SDLK_2,
    SDLK_3,
    SDLK_q,
    SDLK_w,
    SDLK_e,
    SDLK_a,
    SDLK_s,
    SDLK_d,
    SDLK_z,
    SDLK_c,
    SDLK_4,
    SDLK_r,
    SDLK_f,
    SDLK_v,
};

int main(int argc, char **argv) {
#if SnortInsert
	SnortDevice snortDevice = (
		snort_deviceCreateFromCommon(
			kSnortCommonInterface_chip8,
			"griffin",
			argc >= 2 ? argv[1] : "",
			argc,
			(char const * const *)argv
		)
	);
	ImGui::GetIO().IniFilename = "imgui-chip8.ini";
#endif

    // Command usage
    if (argc != 2) {
        cout << "Usage: chip8 <ROM file>" << endl;
        return 1;
    }

    Chip8 chip8 = Chip8();          // Initialise Chip8

    int w = 1024;                   // Window width
    int h = 512;                    // Window height

    // The window we'll be rendering to
#if !SnortInsert
    SDL_Window* window = NULL;

    // Initialize SDL
    if ( SDL_Init(SDL_INIT_EVERYTHING) < 0 ) {
        printf( "SDL could not initialize! SDL_Error: %s\n", SDL_GetError() );
        exit(1);
    }
    // Create window
    window = SDL_CreateWindow(
            "CHIP-8 Emulator",
            SDL_WINDOWPOS_UNDEFINED, SDL_WINDOWPOS_UNDEFINED,
            w, h, SDL_WINDOW_SHOWN
    );
    if (window == NULL){
        printf( "Window could not be created! SDL_Error: %s\n",
                SDL_GetError() );
        exit(2);
    }

    // Create renderer
    SDL_Renderer *renderer = SDL_CreateRenderer(window, -1, 0);
    SDL_RenderSetLogicalSize(renderer, w, h);

    // Create texture that stores frame buffer
    SDL_Texture* sdlTexture = SDL_CreateTexture(renderer,
            SDL_PIXELFORMAT_ARGB8888,
            SDL_TEXTUREACCESS_STREAMING,
            64, 32);

    // Temporary pixel buffer
    uint32_t pixels[2048];
#endif


    load:
    // Attempt to load ROM
    if (!chip8.load(argv[1]))
        return 2;

    // Emulation loop
#if SnortInsert
    while (!snort_shouldQuit(snortDevice)) {
#else
	while (true) {
#endif
#if SnortInsert
		bool const shouldRunFrame = (
			snort_startFrame(
				snortDevice,
				(SnortMemoryRegion const []) {
					{ chip8.memory },
					{ (u8 *)chip8.stack },
					{ chip8.V },
					{ (u8 *)&chip8.I },
					{ (u8 *)&chip8.pc },
					{ (u8 *)&chip8.stack },
					{ chip8.gfx },
				}
			)
		);
		if (shouldRunFrame) {
#endif
        chip8.emulate_cycle();
#if SnortInsert
		}

		snort_endFrame(snortDevice);
#endif

        // Process SDL events
#if !SnortInsert
        SDL_Event e;
        while (SDL_PollEvent(&e)) {
            if (e.type == SDL_QUIT) exit(0);

            // Process keydown events
            if (e.type == SDL_KEYDOWN) {
                if (e.key.keysym.sym == SDLK_ESCAPE)
                    exit(0);

                if (e.key.keysym.sym == SDLK_F1)
                    goto load;      // *gasp*, a goto statement!
                                    // Used to reset/reload ROM

                for (int i = 0; i < 16; ++i) {
                    if (e.key.keysym.sym == keymap[i]) {
                        chip8.key[i] = 1;
                    }
                }
            }
            // Process keyup events
            if (e.type == SDL_KEYUP) {
                for (int i = 0; i < 16; ++i) {
                    if (e.key.keysym.sym == keymap[i]) {
                        chip8.key[i] = 0;
                    }
                }
            }
        }

        // If draw occurred, redraw SDL screen
        if (chip8.drawFlag) {
            chip8.drawFlag = false;

            // Store pixels in temporary buffer
            for (int i = 0; i < 2048; ++i) {
                uint8_t pixel = chip8.gfx[i];
                pixels[i] = (0x00FFFFFF * pixel) | 0xFF000000;
            }
            // Update SDL texture
            SDL_UpdateTexture(sdlTexture, NULL, pixels, 64 * sizeof(Uint32));
            // Clear screen and render
            SDL_RenderClear(renderer);
            SDL_RenderCopy(renderer, sdlTexture, NULL, NULL);
            SDL_RenderPresent(renderer);
        }
#endif

        // Sleep to slow down emulation speed
        std::this_thread::sleep_for(std::chrono::microseconds(1200));

    }

#if SnortInsert
	snort_deviceDestroy(&snortDevice);
#endif
}
