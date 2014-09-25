#include <SDL.h>
#undef main //for VC

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
    
    SDL_Init(SDL_INIT_EVERYTHING);
    SDL_Window *win = SDL_CreateWindow("Spaceship", 50, 50, 250, 250, SDL_WINDOW_SHOWN);
    SDL_Renderer *renderer = SDL_CreateRenderer(win, -1, SDL_RENDERER_ACCELERATED);
    
    Vec2 position(125, 125), velocity(0, 0);
    gatey::WriteVariable<Vec2> gPosition("position"), gVelocity("velocity");
    gatey::ReadVariable<float> gPower("power", 20.0f);

    
    float dt = 1.0f / 30;
    
    std::vector<SDL_Rect> trail;
    
    while (true){
        double tStart = time();
        
        SDL_Event e;
        while (SDL_PollEvent(&e)) {
            if (e.type == SDL_QUIT)
                return 0;
        }
        
        Vec2 acceleration(0, 0);
        Uint8 const* keyboard = SDL_GetKeyboardState(nullptr);
        if(keyboard[SDL_SCANCODE_LEFT]) acceleration += Vec2(-1, 0);
        if(keyboard[SDL_SCANCODE_RIGHT]) acceleration += Vec2(1, 0);
        if(keyboard[SDL_SCANCODE_UP]) acceleration += Vec2(0, -1);
        if(keyboard[SDL_SCANCODE_DOWN]) acceleration += Vec2(0, 1);
        
        velocity += dt * gPower.get() * acceleration;
        position += dt * velocity;
        
        gVelocity.set(velocity);
        gPosition.set(position);
        
		SDL_SetRenderDrawColor(renderer, 0, 0, 0, 255); //black
        SDL_RenderClear(renderer);
        
        SDL_Rect rect = { (int)position.x - 5, (int)position.y - 5, 10, 10 };
		SDL_SetRenderDrawColor(renderer, 255, 255, 255, 255); //white
        SDL_RenderFillRect(renderer, &rect);
        
        SDL_RenderPresent(renderer);
        
        double tEnd = time();
        int tDeltaInMs = (int)(1000.0 * (tEnd - tStart));
        SDL_Delay(std::max(30 - tDeltaInMs, 0));
    }
    
    return 0;
}

