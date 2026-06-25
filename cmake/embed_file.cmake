# Embed a text file as a C byte array with C linkage.
#   cmake -DINPUT=<file> -DOUTPUT=<file.c> -DSYMBOL=<name> -P embed_file.cmake
# Produces:  const char <SYMBOL>[] = { 0x.., ..., 0x00 };  (NUL-terminated)
# HEX read so any byte (incl. CR/LF/UTF-8) round-trips exactly.

file(READ "${INPUT}" _hex HEX)
string(LENGTH "${_hex}" _hexlen)
math(EXPR _n "${_hexlen} / 2")

set(_body "")
set(_i 0)
set(_col 0)
while(_i LESS _n)
    math(EXPR _off "${_i} * 2")
    string(SUBSTRING "${_hex}" ${_off} 2 _byte)
    string(APPEND _body "0x${_byte},")
    math(EXPR _col "${_col} + 1")
    if(_col GREATER_EQUAL 20)
        string(APPEND _body "\n")
        set(_col 0)
    endif()
    math(EXPR _i "${_i} + 1")
endwhile()

file(WRITE "${OUTPUT}"
    "/* Auto-generated from ${INPUT}. Do not edit. */\n"
    "const char ${SYMBOL}[] = {\n"
    "${_body}0x00\n"
    "};\n")
