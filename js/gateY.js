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
    this.receiveGates = {};
    this.remoteReceiveGates = {};
    this.sendGates = {};
    this.remoteSendGates = {};

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

        if(message.cmd == 'state') {
            self.remoteReceiveGates = message.receiveGates;
            self.remoteSendGates = message.sendGates;
        } else if(message.cmd == 'message') {
            if(message.name in self.receiveGates) {
                var onReceive = self.receiveGates[message.name].onReceive;
                if(onReceive)
                    onReceive(message.content);
            }
        }
    };
}

gatey.GateY.prototype.processSendQueue = function() {
    if(!this.connected)
        return;

    for(var i = 0; i < this.sendQueue.length; ++i) {
        var cmd = this.sendQueue[i];
        var cmdStr = JSON.stringify(cmd);
        this.websocket.send(cmdStr);
    }

    this.sendQueue = [];
};

gatey.GateY.prototype.sendCommand = function(command) {
    this.sendQueue.push(command);
    this.processSendQueue();
};

gatey.GateY.prototype.sendState = function() {
    var receiveGates = {};
    for(var key in this.receiveGates) {
        receiveGates[key] = {}
    }
    var sendGates = {};
    for(var key in this.sendGates) {
        sendGates[key] = {}
    }
    var cmd = {cmd: 'state', receiveGates: receiveGates, sendGates: sendGates };
    this.sendCommand(cmd);

};

gatey.GateY.prototype.send = function(name, content) {
    if(!(name in this.sendGates)) {
        //TODO: improve message
        console.warn('not sending message because sendGate with name');
        return;
    }

    if(!(name in this.remoteReceiveGates)) {
        //TODO: improve message
        console.warn("not send message because remoteReceiveGate with name ... doesn't exist");
        return;
    }

    var command = {cmd: 'message', name: name, content: content};
    this.sendCommand(command);
};


gatey.GateY.prototype.openReceiveGate = function(name, onReceive, whenConnected) {
    this.receiveGates[name] = {onReceive: onReceive, whenConnected: whenConnected};
    this.sendState();
};

gatey.GateY.prototype.openSendGate = function(name) {
    this.sendGates[name] = {};
    this.sendState();
};

gatey.GateY.prototype.closeReceiveGate = function(name) {
    delete this.receiveGates[name];
    this.sendState();
};

gatey.GateY.prototype.closeSendGate = function(name) {
    delete this.sendGates[name];
    this.sendState();
};

gatey.global = new gatey.GateY();

/**
 * WriteVariable that is connected to a remote ReadVariable, if it is set the remote ReadVariable
 * will reflect the change
 */
gatey.WriteVariable = function(name, gateY) {
    this.name = name;
    this.gateY = gateY || gatey.global;

    this.gateY.openSendGate(this.name);
}

gatey.WriteVariable.prototype.set = function(value) {
    this.gateY.send(this.name, value);
};

gatey.WriteVariable.prototype.close = function() {
    this.gateY.closeSendGate(this.name);
};

gatey.ReadVariable = function(name, value, gateY) {
    this.name = name;
    this.value = value;
    this.onChange = undefined;
    this.gateY = gateY || gatey.global;

    var self = this;
    this.gateY.openReceiveGate(name, function(value) {
        self.value = value;
        if(self.onChange)
            self.onChange(self.value);
    });
}

gatey.ReadVariable.prototype.get = function() {
    return this.value;
};

gatey.ReadVariable.prototype.close = function() {
    this.gateY.closeReceiveGate(this.name);
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


