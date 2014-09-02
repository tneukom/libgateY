import os.path as path
import itertools

root = ''

def load_file(filename):
    with open (filename, "r") as myfile:
        return myfile.read()

def save_file(str, filename):
    with open(filename, "w") as myfile:
        myfile.write(str)

def source(filename):
    filepath = path.join(root, filename)
    return [
        '/***************************************************',
        ' * ' + filepath,
        ' ***************************************************/',
        '',
        load_file(filepath),
    ]

# def save_source(str, filename):
#     save_file(str, path.join(root, filename))

def concat(ls):
    return list(itertools.chain(*ls))

def flatten(node):
    if isinstance(node, list):
        return [item for sub_ls in node for item in flatten(sub_ls)]
    return [node]

def combine(ls):
    return "\n".join(flatten(ls))

#
# jsoncpp
#

root = 'external/jsoncpp/'

header = [
    '/// Json-cpp amalgated header (http://jsoncpp.sourceforge.net/).',
    '#ifndef JSON_AMALGATED_H_INCLUDED',
    '# define JSON_AMALGATED_H_INCLUDED',
    '#define JSON_IS_AMALGAMATION',

    source('include/json/config.h'),
    source('include/json/forwards.h'),
    source('include/json/features.h'),
    source('include/json/value.h'),
    source('include/json/reader.h'),
    source('include/json/writer.h'),
    source('include/json/assertions.h'),

    '#endif //ifndef JSON_AMALGATED_H_INCLUDED',
]
header_result = combine(header)
save_file(header_result, 'src/json.hpp')


cpp = [
    '/// Json-cpp amalgated source (http://jsoncpp.sourceforge.net/).',

    '#ifndef GATEY_IS_AMALGAMATION',
    '#include "json.hpp"',
    '#endif',

    source('src/lib_json/json_tool.h'),
    source('src/lib_json/json_reader.cpp'),
    source('src/lib_json/json_batchallocator.h'),
    source('src/lib_json/json_valueiterator.inl'),
    source('src/lib_json/json_value.cpp'),
    source('src/lib_json/json_writer.cpp'),
]
cpp_result = combine(cpp)
save_file(cpp_result, 'src/json.cpp')

#
# libwebsockets
#

root = 'external/libwebsockets/'

header = [
    '/*',
    ' * libwebsockets amalgated header (http://jsoncpp.sourceforge.net/).',
    ' */',
    '',

    '#ifndef WEBSOCKET_AMALGATED_H_INCLUDED',
    '#define WEBSOCKET_AMALGATED_H_INCLUDED',
    '#define WEBSOCKET_IS_AMALGAMATION',

    source('src/libwebsockets.h'),

    '#endif //ifndef WEBSOCKET_AMALGATED_H_INCLUDED',
]
header_result = combine(header)
save_file(header_result, 'src/libwebsockets.h')

cpp = [
    '/*',
    ' * libwebsockets amalgated source (http://jsoncpp.sourceforge.net/).',
    ' */',
    '',

    source('src/lws_config.h'),
    source('src/platforms.h'),

    '#ifndef GATEY_IS_AMALGAMATION',
    '#include "libwebsockets.h"',
    '#endif',

    source('src/private-libwebsockets.h'),
    source('src/base64-decode.cpp'),
    source('src/context.cpp'),
    source('src/handshake.cpp'),
    source('src/libwebsockets.cpp'),
    source('src/lws-plat-win.cpp'),
    source('src/lws-plat-unix.cpp'),
    source('src/output.cpp'),
    source('src/parsers.cpp'),
    source('src/pollfd.cpp'),
    source('src/server.cpp'),
    source('src/server-handshake.cpp'),
    source('src/service.cpp'),
    source('src/sha-1.cpp'),
]
cpp_result = combine(cpp)
save_file(cpp_result, 'src/libwebsockets.cpp')

#
# libgatey
#

root = ''

header = [
    '// gatey amalgated header (http://jsoncpp.sourceforge.net/).',
    '#ifndef GATEY_AMALGATED_H_INCLUDED',
    '#define GATEY_AMALGATED_H_INCLUDED',
    '#define GATEY_IS_AMALGAMATION',

    '',
    '/* gateY code',
    ' * Copyright(C) 2014 Tobias Neukom <tneukom@gmail.com>',
    ' * Distributed under MIT license',
    ' */',
    '',

    source('src/Serialize.hpp'),
    source('src/GateY.hpp'),
    source('src/Variable.hpp'),

    '#endif //ifndef GATEY_AMALGATED_H_INCLUDED',
]


header_result = combine(header)
save_file(header_result, 'gatey.hpp')

cpp = [
    '/*',
    ' * gatey amalgated source (http://jsoncpp.sourceforge.net/).',
    ' */',
    '',

    '',
    '/* gateY code',
    ' * Copyright(C) 2014 Tobias Neukom <tneukom@gmail.com>',
    ' * Distributed under MIT license',
    ' */',
    '',

    '#include "gatey.hpp"',

    source('src/json.hpp'),

    source('src/json.hpp'),
    source('src/libwebsockets.h'),

    source('src/WebSocketQueue.hpp'),
    source('src/Log.hpp'),

    source('src/GateY.cpp'),
    source('src/Log.cpp'),
    source('src/Serialize.cpp'),
    source('src/WebSocketQueue.cpp'),

    '',
    '/* jsoncpp code',
    ' * Copyright 2007-2010 Baptiste Lepilleur',
    ' * Distributed under MIT license, or public domain if desired and',
    ' */',
    '',

    source('src/json.cpp'),

    '',
    '/* libwebsockets code',
    ' * Copyright (C) 2010-2013 Andy Green <andy@warmcat.com>',
    ' * Distributed under lesser GPL with static linking exception',
    ' */',
    '',

    source('src/libwebsockets.cpp'),
]
cpp_result = combine(cpp)
save_file(cpp_result, 'gatey.cpp')