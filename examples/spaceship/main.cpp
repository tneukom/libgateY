#include <SDL2/SDL.h>

#include "../../gatey.hpp"
#include <iostream>

//TODO: Fix framereate (is fixed by vsync, but dependent on system)

struct Vec2 {
    float x, y;
    
    Vec2(float x, float y) : x(x), y(y) {}
};

Vec2 operator+(Vec2 const& l, Vec2 const& r) {
    return Vec2 (l.x + r.x, l.y + r.y);
}

Vec2& operator+=(Vec2& l, Vec2 const& r) {
    l = l + r;
    return l;
}

Vec2 operator*(float l, Vec2 const& r) {
    return Vec2(l * r.x, l * r.y);
}

namespace gatey { namespace serialize {
    void write(Vec2 const& value, Json::Value& jValue, Info info) {
        write(std::make_tuple(value.x, value.y), jValue, info);
    }
}}

double time() {
    return (double)SDL_GetPerformanceCounter() / (double)SDL_GetPerformanceFrequency();
}

int main(int argc, const char * argv[])
{
    gatey::global = std::make_shared<gatey::GateY>();
    gatey::WriteVariable<Vec2> gSpaceshipPosition("position");
    gatey::WriteVariable<Vec2> gSpaceShipVelocity("velocity");
    gatey::ReadVariable<float> gAcceleration("acceleration", 1.0f);
    
    SDL_Init(SDL_INIT_EVERYTHING);
    SDL_Window *win = SDL_CreateWindow("Hello World!", 100, 100, 600, 600, SDL_WINDOW_SHOWN);
    SDL_Renderer *renderer = SDL_CreateRenderer(win, -1, SDL_RENDERER_ACCELERATED);
    
    Vec2 spaceshipPosition(300, 300);
    Vec2 spaceshipVelocity(0, 0);
    float dt = 1.0f / 30;
    
    bool quit = false;
    while (!quit){
        double tStart = time();
        
        SDL_Event e;
        while (SDL_PollEvent(&e)){
            if (e.type == SDL_QUIT){
                quit = true;
            }
        }
        
        Vec2 acceleration(0, 0);
        Uint8 const* keyboard = SDL_GetKeyboardState(nullptr);
        if(keyboard[SDL_SCANCODE_LEFT] != 0)
            acceleration = acceleration + Vec2(-1, 0);
        if(keyboard[SDL_SCANCODE_RIGHT] != 0)
            acceleration = acceleration + Vec2(1, 0);
        if(keyboard[SDL_SCANCODE_UP] != 0)
            acceleration = acceleration + Vec2(0, -1);
        if(keyboard[SDL_SCANCODE_DOWN] != 0)
            acceleration = acceleration + Vec2(0, 1);
        spaceshipVelocity += dt * 20 * acceleration;
        spaceshipPosition += dt * spaceshipVelocity;
        
        gSpaceShipVelocity.set(spaceshipVelocity);
        gSpaceshipPosition.set(spaceshipPosition);
        
        
        //Render the scene
        SDL_RenderClear(renderer);
        
        SDL_Rect rect = { (int)spaceshipPosition.x - 5, (int)spaceshipPosition.y - 5, 10, 10 };
        SDL_RenderFillRect(renderer, &rect);
        
        SDL_RenderDrawLine(renderer,
                           (int)spaceshipPosition.x,
                           (int)spaceshipPosition.y,
                           (int)(spaceshipPosition.x + spaceshipVelocity.x),
                           (int)(spaceshipPosition.y + spaceshipVelocity.y));
        
        //renderTexture(image, renderer, x, y);
        SDL_RenderPresent(renderer);
        
        double tEnd = time();
        int tDeltaInMs = (int)(1000.0 * (tEnd - tStart));
        std::cout << tDeltaInMs << std::endl;
        SDL_Delay(std::max(30 - tDeltaInMs, 0));
        
    }
    
    return 0;
}

