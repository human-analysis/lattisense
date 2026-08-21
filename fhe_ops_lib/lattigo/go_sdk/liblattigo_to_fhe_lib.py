import os
from curses.ascii import isupper


def main():
    comments = dict()
    if os.path.isfile('fhe_lib.h'):
        with open('fhe_lib.h', 'r') as f:
            old_fhe_lib_h = f.readlines()
        old_fhe_lib_h = old_fhe_lib_h[6:]
        in_comment = False
        comment_lines = list()
        for line in old_fhe_lib_h:
            line_s = line.rstrip()
            if line_s.startswith('/*'):
                in_comment = True
            if in_comment:
                comment_lines.append(line_s)
                if line_s.endswith('*/'):
                    in_comment = False
            else:
                if line_s == '':
                    continue
                p_pos = line_s.find('(')
                func_name = line_s[:p_pos].split(' ')[-1][2:]
                if comment_lines:
                    comments[func_name] = comment_lines
                    comment_lines = list()

    with open('../lattigo/go_sdk/liblattigo.h', 'r') as f:
        liblattigo = f.readlines()
    start_line = 0
    for i, line in enumerate(liblattigo):
        if line.startswith('extern "C" {'):
            start_line = i + 3
            break
    
    h_f = open('fhe_lib_v2.h', 'w')
    c_f = open('fhe_lib_v2.c', 'w')

    h_f.write('/** @file */\n')
    h_f.write('\n')
    h_f.write('#pragma once\n')
    h_f.write('#include <inttypes.h>\n')
    h_f.write('#include "fhe_types.h"\n')
    h_f.write('\n')

    c_f.write('#include "liblattigo.h"\n')
    c_f.write('#include "fhe_lib.h"\n')
    c_f.write('\n')

    for line in liblattigo[start_line:-4]:
        c_line = line.rstrip().replace('extern ', '').replace('GoUint64', 'uint64_t').replace('GoInt', 'int')
        # print(c_line)

        p_pos = c_line.find('(')
        func_name = c_line[:p_pos].split(' ')[-1]
        lower_func_name = ''
        for i, c in enumerate(func_name):
            if c.isupper():
                if i != 0:
                    lower_func_name += '_'
                lower_func_name += c.lower()
            else:
                lower_func_name += c
        # print(func_name, lower_func_name)

        return_type = c_line[:p_pos].replace(' '+func_name, '')
        # print(return_type)
        arguments = c_line[p_pos+1:-2].split(', ')
        argument_names = [x.split(' ')[-1] for x in arguments]
        # print(argument_names)
        argument_types = [arguments[i].replace(' '+argument_names[i], '') for i in range(len(arguments))]
        # print(argument_types)

        if lower_func_name in comments:
            for comment_line in comments[lower_func_name]:
                h_f.write(comment_line + '\n')

        h_line = return_type + ' c_' + lower_func_name + '(' + ', '.join([x + ' ' + y for x, y in zip(argument_types, argument_names)]) + ');\n'
        h_f.write(h_line)
        h_f.write('\n')

        cpp_line = 'inline ' + return_type + ' c_' + lower_func_name + '(' + ', '.join([x + ' ' + y for x, y in zip(argument_types, argument_names)]) + ') {\n'
        c_f.write(cpp_line)
        cpp_line = '    ' + ('' if return_type == 'void' else 'return ') + func_name + '(' + ', '.join([x for x in argument_names]) + ');\n'
        c_f.write(cpp_line)
        cpp_line = '}\n'
        c_f.write(cpp_line)
        cpp_line = '\n'
        c_f.write(cpp_line)

    h_f.close()
    c_f.close()


if __name__ == '__main__':
    main()
