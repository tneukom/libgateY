libgateY
========

Visualize and control C++ data using the web browser. Single hpp/cpp, no dependencies, OS X, Windows, Linux.

![Native and js screenshots](/images/spaceship.png)

What is it for?
---------------

Use a web browser to easily visualize data from your C++ program and control it’s behaviour. 

Who is it for?
--------------

You have a console application and want to visualize some data it’s producing while it is running. You have a game and don’t want to write ingame interface to control some aspect of it’s behaviour. You found a bug and need to graph the value of some variable to get a better understanding of the faulty behaviour.

What does it do?
----------------

LibGateY helps you send data structures over WebSockets from your C++ program to the web browser and the other way. It can send and receive a large amount of C++ standard types by default. For example std::map<std::string, std::tuple<float, float, float>> will automatically be converted to a JSON object of the form { key0: [x, y, z], key1: [x, y, z] }. The serialization machinery can be extended to support your own types.

How do I use it?
----------------

LibGateY tries to be as simple to deploy as possible, so it consists of only one .hpp and one .cpp file. It doesn’t have any dependecies. Just copy it into your project.

Spaceship example
-----------------


```c++
gatey::global = std::make_shared<gatey::GateY>();

// Init window and graphics (using SDL)

Vec2 position(300, 300), velocity(0, 0);
gatey::WriteVariable<Vec2> gPosition("position"), gVelocity("velocity");
gatey::ReadVariable<float> gPower("power", 20.0f);
float dt = 1.0f / 30;

while (true) {
    Vec2 acceleration(0, 0);
    // Handle input (arrow keys accelerate)
    
    velocity += dt * gPower.get() * acceleration;
    position += dt * velocity;
    gVelocity.set(velocity);
    gPosition.set(position);
    
    // Draw rectangle at position
}
```

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
