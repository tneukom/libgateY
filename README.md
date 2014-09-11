libgateY
========

Visualize and control C++ data using the web browser. Single hpp/cpp, no dependencies, OS X, Windows, Linux.

Simple example:

```c++
int main(int argc, const char * argv[])
{
    gatey::global = std::make_shared<gatey::GateY>();
    
    SDL_Init(SDL_INIT_EVERYTHING);
    auto win = SDL_CreateWindow("Spaceship", 0, 0, 600, 600, SDL_WINDOW_SHOWN);
    auto renderer = SDL_CreateRenderer(win, -1, SDL_RENDERER_ACCELERATED);
    
    Vec2 position(300, 300), velocity(0, 0);
    gatey::WriteVariable<Vec2> gPosition("position"), gVelocity("velocity");
    gatey::ReadVariable<float> gPower("power", 20.0f);
    float dt = 1.0f / 30;
    
    while (true) {
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
        
        SDL_RenderClear(renderer);
        
        SDL_Rect rect = { (int)position.x - 5, (int)position.y - 5, 10, 10 };
        SDL_RenderFillRect(renderer, &rect);
        
        SDL_RenderPresent(renderer);
    }
    
    return 0;
}
```

JavaScript

```javascript
var gPosition = new gatey.ReadVariable('position', 0);
var gVelocity = new gatey.ReadVariable('velocity', 0);
var gPower = new gatey.WriteVariable('power');

function slideUpdate() {
    gPower.set($("#slider_a").slider("value"));
}

$(function() {
    $('#slider_a').slider({
        min: 0, max: 100, value: 20,
        slide: slideUpdate, change: slideUpdate
    });
});

var canvas = document.getElementById('spaceship_trace');
var ctx = canvas.getContext('2d');

var lastPos = undefined;
gPosition.onChange = function(newPos) {
    if(lastPos) {
        ctx.beginPath();
        ctx.moveTo(lastPos[0], lastPos[1]);
        ctx.lineTo(newPos[0], newPos[1]);
        ctx.stroke();

        $('#position').html(JSON.stringify(newPos));
    }

    lastPos = newPos;
};
```
