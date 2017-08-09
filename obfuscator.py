###
#
# This tool provides the following operations:
#   1. Defined classes name
#   2. Defined function name
#   3. Called classes name
#   4. Called function name
#   5. Remove comments
#   6. Variables
#
###
import os
import ast
import sys
import astor
import logging
import hashlib
import ConfigParser
from base64 import b64encode, b64decode

log = logging.getLogger('myapp')
hdlr = logging.FileHandler('obf_log')
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
hdlr.setFormatter(formatter)
log.addHandler(hdlr) 
log.setLevel(logging.DEBUG)

def encrypt_str(text):
    ascii_list = []
    ascii_sum = 0
    for c in text:
        ord_c = ord(c)
        ascii_sum += ord_c
        ascii_list.append(ord_c)

    if len(ascii_list) == 0:
        return None

    key = ascii_sum % 128
    enc_sum = key
    for i in xrange(0, len(ascii_list)):
        ascii_list[i] = ascii_list[i] ^ (key >> (i % 4))
        enc_sum += ascii_list[i]

    key_pos = enc_sum % len(ascii_list)
    enc_list = []
    for i in xrange(0, len(ascii_list)):
        if i == key_pos:
            enc_list.append(chr(key))

        enc_list.append(chr(ascii_list[i]))
    return b64encode(''.join(enc_list))

def get_name(item):
    if isinstance(item, ast.Name):
        return item.id
    elif hasattr(item, 'value'):
        return get_name(item.value)
    else:
        return None


class Modifier(ast.NodeTransformer):
   
    def __init__(
        self,
        names,
        name_in_module,
        name_type_def,
        imported,
        skip_obf_fun_method,
        in_file
    ):
        self.names = names
        self.name_in_module = name_in_module
        self.name_type_def = name_type_def
        self.imported = imported
        self.skip_obf_fun_method = skip_obf_fun_method
        self.in_def = ''
        self.in_def_stack = []
        self.in_file = in_file
        super(Modifier, self).__init__()

    def _check_n_encrypt_str(self, node):
        if not isinstance(node, ast.Str):
            return None

        ciphertext = encrypt_str(node.s)
        decrypt_ast = ast.parse(
            "%s(\"%s\")" % (
                self.name_type_def['decrypt_str']['obf'], ciphertext
            )
        )
        return decrypt_ast.body[0].value
        
    def _modify_func_args(self, args):
        for arg in args:
            if isinstance(arg, ast.Name):
                self._modify_name(arg, 'arg')

    def _modify_node(self, node, attribute, t=None):
        encrypted_str = self._check_n_encrypt_str(getattr(node, attribute))
        if encrypted_str is not None:
            setattr(node, attribute, encrypted_str)
        else:
            self._modify_node_attr(getattr(node, attribute), t)

    def _modify_node_attr(self, item, t=None):
        if isinstance(item, ast.Name):
            self._modify_name(item, t)
        elif isinstance(item, ast.Attribute):
            self._modify_attr(item, t)
        elif isinstance(item, ast.BinOp):
            self._modify_node_attr(item.left, t)
            self._modify_node_attr(item.right, t)
        elif isinstance(item, ast.Call):
            self._modify_call(item)
        elif isinstance(item, ast.Compare):
            self._modify_node_attr(item.left, t)
            for comparator in item.comparators:
                self._modify_node_attr(comparator)
        elif isinstance(item, ast.comprehension):
            self._modify_node_attr(item.target)
            self._modify_node_attr(item.iter)
        elif isinstance(item, ast.Dict):
            for key in item.keys:
                self._modify_node_attr(key)

            for value in item.values:
                self._modify_node_attr(value)
        elif isinstance(item, ast.ExtSlice):
            for dim in item.dims:
                self._modify_node_attr(dim)
        elif isinstance(item, ast.Index):
            self._modify_node_attr(item.value)
        elif isinstance(item, ast.List):
            for elt in item.elts:
                self._modify_node_attr(elt)
        elif isinstance(item, ast.ListComp):
            self._modify_node_attr(item.elt, t)
            for gen in item.generators:
                self._modify_node_attr(gen, t)
        elif isinstance(item, ast.Tuple):
            for elt in item.elts:
                self._modify_node_attr(elt, t)
        elif isinstance(item, ast.Slice):
            self._modify_node_attr(item.lower, t)
            self._modify_node_attr(item.upper, t)
        elif isinstance(item, ast.Subscript):
            self._modify_node_attr(item.value)
            self._modify_node_attr(item.slice)
        elif isinstance(item, ast.UnaryOp):
            self._modify_node_attr(item.operand)

    def _modify_attr_attr(self, func_name, attr):
        if (
            func_name in self.skip_obf_fun_method and \
            self.in_def in self.skip_obf_fun_method[func_name]
        ):
            # We only obfuscate the attr field of an Attribute of that function
            # which is not in the skipping list.
            return None

        if (
            attr.attr in self.name_type_def and \
            'attr' in self.name_type_def[attr.attr]
        ):
            attr.attr = self.name_type_def[attr.attr]['obf']

    def _modify_attr(self, attr, t=None):
        attr_name = get_name(attr)
        if isinstance(attr.value, ast.Name):
            if attr.value.id in self.imported[self.in_file]:
                return None

            if attr_name != "self":
                self._modify_node_attr(attr.value, t)

            self._modify_attr_attr(attr_name, attr)
        else:
            self._modify_attr_attr(attr_name, attr)
            self._modify_node_attr(attr.value, t)
        
    def _modify_call(self, node):
        self._modify_node_attr(node.func, 'func')
        self._modify_call_args(node.args)
        self._modify_call_keywords(node.keywords)

    def _modify_call_args(self, args):
        for arg in args:
            self._modify_node_attr(arg, 'var')
            self._modify_node_attr(arg, 'arg')
            self._modify_node_attr(arg, 'func')

    def _modify_call_keywords(self, keywords):
        for keyword in keywords:
            self._modify_node_attr(keyword.value)

    def _modify_name(self, name, t):
        if not isinstance(name, ast.Name):
            return None

        if t is None:
            t = 'var'

        if name.id in self.imported[self.in_file]:
            # We don't obfuscate the imported/outside module which is not in our
            # project path.
            return None

        if name.id in self.name_type_def:
            log.debug("_modify_name: %s (%s) [%s]" % (name.id, self.in_def, t))
            if (
                ('var' in self.name_type_def[name.id]) or \
                (
                    'arg' in self.name_type_def[name.id] and \
                    self.in_def in self.name_type_def[name.id]['arg']
                ) or \
                ('func' in self.name_type_def[name.id]) or \
                ('class' in self.name_type_def[name.id])
            ):
                name.id = self.name_type_def[name.id]['obf']
            log.debug("after _modify_name: %s" % name.id)

    def visit_Assign(self, node):
        log.debug("[modifier] assign: %s" % ast.dump(node))
        for target in node.targets:
            self._modify_node_attr(target, 'var')

        self._modify_node(node, 'value')
        log.debug("[modifier] after assign: %s" % ast.dump(node))
        return node

    def visit_AugAssign(self, node):
        log.debug("[modifier] augassign: %s" % ast.dump(node))
        self._modify_node_attr(node.target)
        self._modify_node_attr(node.value)
        return node

    def visit_Call(self, node):
        def _get_func_name(func):
            if isinstance(func, ast.Name):
                return func.id
            elif hasattr(func, 'value'):
                return _get_func_name(func.value)

            return None

        log.debug("[modifier] call: %s" % ast.dump(node))
        self._modify_call(node)
        log.debug("[modifier] after: %s" % ast.dump(node))
        return node

    def visit_ClassDef(self, node):
        log.debug("[modifier] class: %s" % node.name)
        self.in_def = node.name
        if node.name in self.name_type_def:
            node.name = self.name_type_def[node.name]['obf']

        self.generic_visit(node)
        return node

    def visit_Delete(self, node):
        log.debug("[modifier] delete: %s" % ast.dump(node))
        for target in node.targets:
            self._modify_node_attr(target)

        return node

    def visit_Expr(self, node):
        """
        Drop comments
        """
        log.debug("[modifier] expr: %s" % ast.dump(node))
        if isinstance(node.value, ast.Str):
            return None
        else:
            self.generic_visit(node)
            return node

    def visit_FunctionDef(self, node):
        log.debug("[modifier] func: %s" % ast.dump(node))
        self.in_def_stack.append(self.in_def)
        self.in_def = node.name
        if (
            node.name in self.name_type_def and \
            node.name in self.name_type_def[node.name]['func']
        ):
            node.name = self.name_type_def[node.name]['obf']

        self._modify_func_args(node.args.args)
        self.generic_visit(node)
        self.in_def = self.in_def_stack.pop()
        return node

    def visit_For(self, node):
        log.debug("[modifier] for: %s" % ast.dump(node))
        self._modify_node_attr(node.target)
        self._modify_node_attr(node.iter)
        self.generic_visit(node)
        return node

    def visit_If(self, node):
        log.debug("[modifier] if: %s" % ast.dump(node))
        if isinstance(node.test, ast.Compare):
            self._modify_node_attr(node.test.left)
        elif isinstance(node.test, ast.UnaryOp):
            self._modify_node_attr(node.test.operand)
        elif isinstance(node.test, ast.BoolOp):
            for value in node.test.values:
                self._modify_node_attr(value)
        else:
            self._modify_node_attr(node.test)

        self.generic_visit(node)
        return node

    def visit_Print(self, node):
        log.debug("[modifier] print: %s" % ast.dump(node))
        for value in node.values:
            self._modify_node_attr(value)

        return node

    def visit_Return(self, node):
        log.debug("[modifier] return: %s" % ast.dump(node))
        self._modify_node_attr(node.value)
        return node

    def visit_Str(self, node):
        log.debug("[modifier] str: %s" % ast.dump(node))
        node = self._check_n_encrypt_str(node)
        return node

    def visit_While(self, node):
        log.debug("[modifier] while: %s" % ast.dump(node))
        for value in node.test.values:
            self._modify_node_attr(value)

        self.generic_visit(node)
        return node

class Obfuscator:
    """
    This class is a obfuscator for classes, functions, and variables.
    Methods:
        - load_file: giving the path of a python file. The class, function and
          variable names of this file will be retrieved. Duplicated names in
          different files will be record only once.
        - obfuscate:
    """

    def __init__(self, base_dir):
        self.base_dir = base_dir + "/"
        self.names = {}
        self.imported = {}
        self.skip_obf_fun_method = {}
        self.name_in_module = {}

        # name_type_def: {
        #     "FILE": {
        #         "NAME": {
        #             "TYPE": ["IN_DEF"],
        #             "obf": ''
        #         }, {...}
        #     }, {...}
        # }
        self.name_type_def = {}
        self._name_len = 0
        self.config = self._get_config()
        
        # Load decrypt_str function
        self._decrypt_str_ast = self._parse_file_ast("decrypt_str.py").body[0]

    def _append_dict(self, target, source):
        for item in source:
            target[item] = ''

    def _get_config(self):
        default_config = "obfuscator.config"
        config_parser = ConfigParser.RawConfigParser()
        config_parser.read(default_config)
        config = {}
        config_items = [
            "skip_file", "skip_class", "skip_function", "skip_variable"
        ]
        for item in config_items:
            config[item] = config_parser.get("obfuscator", item).split(",")
        
        return config

    def _get_namelen_bin(self):
        return len(format(self._name_len, "b"))

    def _insert_func(self, node):
        i = 0
        for item in node.body:
            if(
                isinstance(item, ast.FunctionDef) or \
                isinstance(item, ast.ClassDef)
            ):
                break

            i += 1

        node.body.insert(i, self._decrypt_str_ast)
        return node

    def _parse_file_ast(self, filepath):
        if filepath.replace(self.base_dir, '') in self.config["skip_file"]:
            return None

        f = open(filepath, "r")
        content = f.read()
        f.close()
        if len(content) == 0:
            return None

        return ast.parse(content)

    def load_file(self, filepath):
        node = self._parse_file_ast(filepath)
        if node is None:
            return None

        node = self._insert_func(node)
        log.debug("node: %s" % ast.dump(node))
        v = Parser(self.config)
        v.visit(node)
        self._append_dict(self.names, v.names)
        tmp = {}
        self._append_dict(tmp, v.imported)
        self.imported[filepath] = tmp
        for name in v.skip_obf_fun_method:
            if name in self.skip_obf_fun_method:
                for fun in v.skip_obf_fun_method[name]:
                    self.skip_obf_fun_method[name] = fun
            else:
                self.skip_obf_fun_method[name] = v.skip_obf_fun_method[name]

        self.name_in_module[filepath] = v.names
        self.name_type_def[filepath] = v.name_type_def

    def _get_namelen(self, name_type_def):
        max_len = 0
        for f in name_type_def:
            max_len += len(name_type_def[f])

        return max_len

    def obfuscate(self):
        idx = 1
        self._name_len = self._get_namelen(self.name_type_def)
        bin_len = len(format(self._name_len, "b"))
        for f in self.name_type_def:
            for name in self.name_type_def[f]:
                self.name_type_def[f][name]['obf'] = format(
                    idx, "0%db" % (bin_len))
                self.name_type_def[f][name]['obf'] = \
                    self.name_type_def[f][name]['obf']\
                    .replace("1", "l")\
                    .replace("0", "i")
                idx += 1

    def modify_file(self, filepath):
        log.debug("modify_file: %s (%s)" % (self.imported, filepath))
        if filepath.replace(self.base_dir, '') in self.config["skip_file"]:
            return None

        f = open(filepath, "r")
        content = f.read()
        f.close()
        if len(content) == 0:
            return None

        node = ast.parse(content)
        node = self._insert_func(node)
        m = Modifier(
            self.names,
            self.name_in_module[filepath],
            self.name_type_def[filepath],
            self.imported,
            self.skip_obf_fun_method,
            filepath
        )
        mnode = m.visit(node)
        f = open(filepath, "w")
        content = astor.to_source(mnode)
        f.write(content)
        f.close()


class Parser(ast.NodeVisitor):
    """
    This is an AST visitor to parse a given ast node and retrieve classes,
    functions and variables.
    """
    
    def __init__(self, config):
        self.names = []
        self.imported = []
        self.config = config
        self.in_def = ''
        self.in_def_stack = []
        self.skip_obf_fun_method = {}
        self.name_type_def = {}
        super(Parser, self).__init__()

    def _add_name(self, name, t):
        if self._skip_name(name, t):
            return None

        if name not in self.name_type_def:
            self.name_type_def[name] = {}

        if t not in self.name_type_def[name]:
            self.name_type_def[name][t] = []

        self.name_type_def[name][t].append(self.in_def)
        self.name_type_def[name]['obf'] = ''

    def _skip_name(self, name, t):
        if t == 'var' and name in self.config['skip_variable']:
            return True

        return False
    
    def _get_args(self, args):
        for arg in args:
            if isinstance(arg, ast.Name):
                if arg.id != 'self':
                    self._add_name(arg.id, 'arg')

    def _get_import_names(self, names):
        for name in names:
            if name.asname is None:
                self.imported.append(name.name)
            else:
                self.imported.append(name.asname)

    def _get_assign_name(self, target):
        if isinstance(target, ast.Name):
            self._add_name(target.id, 'var')
        elif isinstance(target, ast.Tuple):
            for elt in target.elts:
                self._get_assign_name(elt)
        elif isinstance(target, ast.Attribute):
            self._get_assign_name(target.value)
            if get_name(target.value) == "self":
                self._add_name(target.attr, 'attr')
        elif hasattr(target, 'value'):
            self._get_assign_name(target.value)

    def _get_fun_name(self, func):
        if isinstance(func, ast.Attribute):
            return self._get_fun_name(func.value)
        elif isinstance(func, ast.Name):
            return func.id

    def generic_visit(self, node):
        ast.NodeVisitor.generic_visit(self, node)

    def visit_Assign(self, node):
        log.debug("visit assign: %s" % ast.dump(node))
        for target in node.targets:
            self._get_assign_name(target)

        ast.NodeVisitor.generic_visit(self, node)

    def visit_ClassDef(self, node):
        self.in_def_stack.append(node.name)
        self.in_def = node.name
        if node.name not in self.config['skip_class']:
            self._add_name(node.name, 'class')

        ast.NodeVisitor.generic_visit(self, node)
        self.in_def = self.in_def_stack.pop()

    def visit_For(self, node):
        log.debug("visit for: %s" % ast.dump(node))
        self._get_assign_name(node.target)
        ast.NodeVisitor.generic_visit(self, node)

    def visit_FunctionDef(self, node):
        self.in_def_stack.append(node.name)
        self.in_def = node.name
        if (
            not node.name.startswith("__") and \
            node.name not in self.config['skip_function']
        ):
            self._add_name(node.name, 'func')

        self._get_args(node.args.args)
        ast.NodeVisitor.generic_visit(self, node)
        self.in_def = self.in_def_stack.pop()

    def visit_Import(self, node):
        log.debug("[parser] visit import: %s" % ast.dump(node))
        self._get_import_names(node.names)
        ast.NodeVisitor.generic_visit(self, node)

    def visit_ImportFrom(self, node):
        log.debug("[parser] visit from: %s" % ast.dump(node))
        self._get_import_names(node.names)
        ast.NodeVisitor.generic_visit(self, node)

    def visit_Return(self, node):
        log.debug("[parser] visit return: %s" % ast.dump(node))
        ast.NodeVisitor.generic_visit(self, node)

if __name__ == '__main__':
    if len(sys.argv) <= 1:
        print("Usage: python obfuscator.py [PROJECT_PATH | PYTHON_FILE]")
        sys.exit(0)

    obf_path = sys.argv[1]
    obf = Obfuscator(obf_path)
    if os.path.isfile(obf_path):
        obf.load_file(obf_path)
    else:
        for dirPath, dirNames, fileNames in os.walk(obf_path):
            for f in fileNames:
                fn, ext_fn = os.path.splitext(f)
                if ext_fn == ".py":
                    filepath = os.path.join(dirPath, f)
                    obf.load_file(filepath)

    obf.obfuscate()
    log.debug("names")
    log.debug(obf.names)
    log.debug("name_type_def")
    log.debug(obf.name_type_def)
    log.debug("imported")
    log.debug(obf.imported)
    log.debug("skip_obf_fun_method")
    log.debug(obf.skip_obf_fun_method)

    if os.path.isfile(obf_path):
        obf.modify_file(obf_path)
    else:
        for dirPath, dirNames, fileNames in os.walk(obf_path):
            for f in fileNames:
                fn, ext_fn = os.path.splitext(f)
                if ext_fn == ".py":
                    obf.modify_file(os.path.join(dirPath, f))
