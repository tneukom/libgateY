TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt
CONFIG += c++11

LIBS += -lws2_32

SOURCES += \
    ../../src/GateY.cpp \
    ../../src/json.cpp \
    ../../src/libwebsockets.cpp \
    ../../src/Log.cpp \
    ../../src/main.cpp \
    ../../src/Serialize.cpp \
    ../../src/WebSocketQueue.cpp

HEADERS += \
    ../../src/GateY.hpp \
    ../../src/json.hpp \
    ../../src/libwebsockets.h \
    ../../src/Log.hpp \
    ../../src/Serialize.hpp \
    ../../src/Variable.hpp \
    ../../src/WebSocketQueue.hpp

