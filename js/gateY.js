/**
 * Created by tneukom on 21.08.2014.
 */
"use strict";

//TODO: Don't auto connect!

var gatey = {}

gatey.GateY = function() {
    this.websocket = new WebSocket('ws://127.0.0.1:9000', 'gatey');
    this.websocket.binaryType = "arraybuffer";
    this.connected = false;
    this.subscriptions = [];
    this.remoteSubscriptions = [];
    this.emitters = [];
    this.remoteEmitters = [];

    this.sendQueue = [];

    var self = this;

    this.websocket.onopen = function () {
        self.connected = true;
        console.log('gateY connected!');

        self.sendCommand({cmd: 'init'});
        self.processSendQueue();
    };

    this.websocket.onerror = function () {
        console.log('gateY connection error');
    };

    this.websocket.onclose = function() {
        console.log('gateY disconnected');
    };

    this.websocket.onmessage = function (socketMessage) {
        var message = JSON.parse(socketMessage.data);
        console.log("receiving: ", JSON.stringify(message));

        if(message.cmd == 'state') {
            self.remoteSubscriptions = message.subscriptions;
            self.remoteEmitters = message.emitters;
        } else if(message.cmd == 'message') {
            var found = gatey.firstWithProperties(self.subscriptions, { name: message.name });

//            var found = self.findSubscription(message.name)
            if(found && found.value.onReceive) {
                found.value.onReceive(message.content);
            }
//            if(message.name in self.receiveGates) {
//                var onReceive = self.receiveGates[message.name].onReceive;
//                if(onReceive)
//                    onReceive(message.content);
//            }
        }
    };
}

gatey.hasProperties = function(obj, properties) {
    //TODO: direct properties? Use for of
    for(var property in properties) {
        if(!properties.hasOwnProperty(property)) {
            continue;
        }

        if(obj[property] != properties[property]) {
            return false;
        }

//        if(!obj.hasOwnProperty(property)) {
//            return false;
//        }
//
//        if(obj[property] != properties[property]) {
//            return false;
//        }
    }

    return true;
}

// Removes all elements with properties from ls, returns the removed items
gatey.keepWithProperties = function(ls, properties) {
    var kept = [];
    var rest = [];
    //TODO: Use for.. of
    for(var obj in ls) {
        if(gatey.hasProperties(obj, properties)) {
            kept.push(obj);
        } else {
            rest.push(obj);
        }
    }

    return { kept: kept, rest: rest };
}

gatey.removeWithProperties = function(ls, properties) {
    var keep = keepWithProperties(ls, properties);
    return { rest: keep.kept, removed: keep.rest };
}

gatey.firstWithProperties = function(ls, properties) {
    //TODO: Use for..of
    for(var i = 0; i < ls.length; ++i) {
        var obj = ls[i];
        if(gatey.hasProperties(obj, properties)) {
            return { index: i, value: obj };
        }
    }

    return undefined;
}

gatey.GateY.prototype.processSendQueue = function() {
    if(!this.connected)
        return;

    for(var i = 0; i < this.sendQueue.length; ++i) {
        var cmd = this.sendQueue[i];
        var cmdStr = JSON.stringify(cmd);
        console.log("sending: ", cmdStr);
        this.websocket.send(cmdStr);
    }

    this.sendQueue = [];
};

gatey.GateY.prototype.sendCommand = function(command) {
    this.sendQueue.push(command);
    this.processSendQueue();
};

gatey.GateY.prototype.sendState = function() {
    var jSubscriptions = [];
    //TODO: map
    this.subscriptions.forEach(function(subscription) {
        var jSubscription = {
            name: subscription.name
        };
        jSubscriptions.push(jSubscription);
    });

    var jEmitters = [];
    this.emitters.forEach(function(emitter) {
        var jEmitter = {
            name: emitter.name
        }
        jEmitters.push(jEmitter);
    });

    var cmd = {cmd: 'state', subscriptions: jSubscriptions, emitters: jEmitters };
    this.sendCommand(cmd);

};

gatey.GateY.prototype.send = function(name, content) {
    if(!gatey.firstWithProperties(this.emitters, { name: name })) {
        //TODO: improve message
        console.warn("not sending message because emitter " + name + " doesn't exist");
        return;
    }

    if(!gatey.firstWithProperties(this.remoteSubscriptions, { name: name })) {
        //TODO: improve message
        console.warn("not sending message because remote subscription to " + name + " doesn't exist");
        return;
    }

    var command = {cmd: 'message', name: name, content: content};
    this.sendCommand(command);
};


gatey.GateY.prototype.subscribe = function(name, onReceive, whenConnected) {
    var subscription = gatey.firstWithProperties(this.subscriptions, { name: name });
    if(subscription) {
        subscription.onReceive = onReceive;
        subscription.whenConnected = whenConnected;
        return;
    }

    this.subscriptions.push({
        name: name,
        onReceive: onReceive,
        whenConnected: whenConnected
    });

    this.sendState();
};

gatey.GateY.prototype.unsubscribe = function(name) {
    var result = gatey.removeWithProperties(this.subscriptions, { name: name });
    if(result.removed.length > 0) {
        this.subscriptions = result.rest;
        this.sendState();
    }
}

gatey.GateY.prototype.openEmitter = function(name) {
    var emitter = gatey.firstWithProperties(this.emitters, { name: name });
    if(emitter) {
        return;
    }

    this.emitters.push({
        name: name
    });

    this.sendState();
};

gatey.GateY.prototype.closeEmitter = function(name) {
    var result = gatey.removeWithProperties(this.emitters, { name: name });
    if(result.removed.length > 0) {
        this.emitters = result.rest;
        this.sendState();
    }
};

gatey.global = new gatey.GateY();

/**
 * WriteVariable that is connected to a remote ReadVariable, if it is set the remote ReadVariable
 * will reflect the change
 */
gatey.WriteVariable = function(name, gateY) {
    this.name = name;
    this.gateY = gateY || gatey.global;

    this.gateY.openEmitter(this.name);
}

gatey.WriteVariable.prototype.set = function(value) {
    this.gateY.send(this.name, value);
};

gatey.WriteVariable.prototype.close = function() {
    this.gateY.closeEmitter(this.name);
};

gatey.ReadVariable = function(name, value, gateY) {
    this.name = name;
    this.value = value;
    this.onChange = undefined;
    this.gateY = gateY || gatey.global;

    var self = this;
    this.gateY.subscribe(name, function(value) {
        self.value = value;
        if(self.onChange)
            self.onChange(self.value);
    });
}

gatey.ReadVariable.prototype.get = function() {
    return this.value;
};

gatey.ReadVariable.prototype.close = function() {
    this.gateY.unsubscribe(this.name);
};

gatey.Recorder = function(variable) {
    this.variable = variable;
    this.history = [];
    this.onChange = undefined;

    var self = this;

    variable.onChange = function(value) {
        self.history.push(value);
        if(self.onChange)
            self.onChange(self.value);
    }
}


