TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt
CONFIG += c++11

LIBS += -lws2_32

SOURCES += \
    ../../examples/sin/main.cpp \
    ../../gatey.cpp

HEADERS += \
    ../../gatey.hpp

