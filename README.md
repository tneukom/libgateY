libgateY
========

Visualize and control C++ data using the web browser. Single hpp/cpp, no dependencies, OS X, Windows, Linux.

Simple example:

```c++
int main(int argc, const char * argv[])
{
    gatey::global = std::make_shared<gatey::GateY>();
    
    SDL_Init(SDL_INIT_EVERYTHING);
    SDL_Window *win = SDL_CreateWindow("Spaceship", 50, 50, 600, 600, SDL_WINDOW_SHOWN);
    SDL_Renderer *renderer = SDL_CreateRenderer(win, -1, SDL_RENDERER_ACCELERATED);
    
    Vec2 position(300, 300), velocity(0, 0);
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
        
        SDL_RenderClear(renderer);
        
        SDL_Rect rect = { (int)position.x - 5, (int)position.y - 5, 10, 10 };
        SDL_RenderFillRect(renderer, &rect);
        
        SDL_RenderPresent(renderer);
        
        double tEnd = time();
        int tDeltaInMs = (int)(1000.0 * (tEnd - tStart));
        SDL_Delay(std::max(30 - tDeltaInMs, 0));
    }
    
    return 0;
}
```

JavaScript

```html
<!DOCTYPE html>
<meta charset="utf-8">
<html>
<body>
<link href="http://code.jquery.com/ui/1.11.0/themes/smoothness/jquery-ui.min.css" rel="stylesheet" type="text/css" />
<script src="http://code.jquery.com/jquery-1.11.0.min.js"></script>
<script src="http://code.jquery.com/ui/1.11.0/jquery-ui.min.js"></script>
<script src="gateY.js"></script>
<script>
    "use strict";

    var gDt, gC, gY;

    function refresh() {
        gC.set($("#slider_c").slider("value") / 100);
        gDt.set($("#slider_dt").slider("value") / 1000)
    }

    $(function() {
        $('#slider_dt').slider({
            min: 0, max: 100, value: 1,
            slide: refresh,
            change: refresh
        });

        $('#slider_c').slider({
            min: 0, max: 100, value: 1,
            slide: refresh,
            change: refresh
        });
    });

    $(document).ready(function() {

        gDt = new gatey.WriteVariable('dt');
        gC = new gatey.WriteVariable('c');
        gY = new gatey.ReadVariable('y', 0);

        gY.onChange = function(xs) {
            $('#y').html(JSON.stringify(xs));
        };
    });
</script>
<div id="slider_dt"></div>
<div id="slider_c"></div>
<h1 id="y"></h1>
</body>
</html>
```
