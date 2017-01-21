from cement.core.foundation import CementApp
from cement.core.controller import CementBaseController, expose
import ast, types

class ModifyTree(ast.NodeTransformer):
    def __init__(self, importsToRemove, possibleModules, aliasMap, reverseAliasMap):
        self.importsToRemove = importsToRemove
        self.possibleModules = possibleModules
        self.aliasMap = aliasMap
        self.reverseAliasMap = reverseAliasMap

    def visit_Import(self, node):
        for candidate in self.possibleModules:
            for name in node.names:
                if candidate == name.name:
                    node.names.remove(name)
        if len(node.names) == 0:
            return None
        return node

    def visit_ImportFrom(self, node):
        if node.module in self.possibleModules:
            return None
        return node

    def visit_Call(self, node):
        if isinstance(node.func, ast.Attribute):
            if node.func.value.id in self.importsToRemove: #call.attribute.name.string
                return ast.Call(func=ast.Name(id=node.func.attr, ctx=ast.Load()), args=node.args, keywords=node.keywords, starargs=node.starargs, kwargs=node.kwargs)
        elif isinstance(node.func, ast.Name):
            if node.func.id in self.importsToRemove:
                try:
                    return ast.Call(func=ast.Name(id=self.reverseAliasMap[node.func.id], ctx=ast.Load()), args=node.args, keywords=node.keywords, starargs=node.starargs, kwargs=node.kwargs)
                except KeyError:
                    pass
        return node

class SpecialtyVisitor(ast.NodeVisitor):
    def __init__(self, possibleModules):
        self.stack = 0
        self.classDefinitions = []
        self.alias = {}
        self.reverse_alias = {}
        self.importsToRemove = []
        self.possibleModules = possibleModules # This would come from the commandline args in enc.py
        self.formattedModules = []

    def visit_ClassDef(self, node):
        self.classDefinitions.append(node.name)
        self.generic_visit(node)

    def visit_Import(self, node):
        for importStatement in node.names:
            if importStatement.asname != None:
                self.alias[importStatement.name] = importStatement.asname
                self.reverse_alias[importStatement.asname] = importStatement.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        for importStatement in node.names:
            if importStatement.asname != None:
                self.alias[importStatement.name] = importStatement.asname
                self.reverse_alias[importStatement.asname] = importStatement.name
        self.generic_visit(node)

    def resolve(self):
        import os
        for mod in self.possibleModules:
            module_name = os.path.splitext(mod)[0] # 'A.py' -> 'A'
            self.formattedModules.append(module_name)
            if module_name in self.alias:
                self.importsToRemove.append(self.alias[module_name]) 
            else:
                self.importsToRemove.append(module_name)

class SourceEncryptor(object):
    def __init__(self):
        pass

    def merge_and_encrypt(self, sources, entry, secret, storage_type, compress, debug):
        merged_source_ast = self.merge_source_code(sources, entry)
        merged_source_ast = self.resolve_imports(merged_source_ast, sources)
        if storage_type == 'a': #store file either as an AST or as raw source code
            import cPickle
            output_data = cPickle.dumps(merged_source_ast, protocol=cPickle.HIGHEST_PROTOCOL)
        else:
            import re, astunparse
            output_data = re.sub("[\n]+", "\n", astunparse.unparse(merged_source_ast))

        if compress:
            output_data = self.compress_data(output_data)

        if debug:
            import astunparse
            print astunparse.unparse(merged_source_ast)

        return self.encrypt(output_data, secret) # returns a tuple (computed_iv, encrypted source)

    def resolve_imports(self, tree, sources):
        information_gatherer = SpecialtyVisitor(sources)
        information_gatherer.visit(tree)
        information_gatherer.resolve()
        transformed = ModifyTree(information_gatherer.importsToRemove, information_gatherer.formattedModules, information_gatherer.alias, information_gatherer.reverse_alias)
        transformed.visit(tree)
        ast.fix_missing_locations(tree)
        return tree

    def compress_data(self, data):
        import zlib
        return zlib.compress(data)

    def encrypt(self, source, secret):
        from Crypto.Cipher import AES
        from Crypto.Hash import SHA256
        from Crypto.Random import random

        h = SHA256.new()
        h_iv = SHA256.new()
        
        h.update(bytes(secret))
        h_iv.update(bytes(random.getrandbits(256)))
        computed_iv = h_iv.digest()[:16]

        encryptor = AES.new(h.digest(), AES.MODE_CBC, computed_iv) #Use only the first 16 bytes of the IV hash value
        if len(source) % 16 != 0:
            source += ' ' * (16 - len(source) % 16) # Should note that padding could harm PEP8 compliance...perhaps remove whitespace in Run application
        return (computed_iv, encryptor.encrypt(source))

    def merge_source_code(self, sources, entry):
        tree = None
        for source in sources:
            if source != entry:
                if not tree:
                    tree = self.sanitize_source(source)
                else:
                    tree.body += self.sanitize_source(source).body
        with open(entry,"r") as fin:
            if not tree: 
                tree = ast.parse(fin.read())
            else:
                tree.body += ast.parse(fin.read()).body
        return tree #returns an ast

        # TODO: You should be pickling this...there is no reason to bring it back to a human readable version unless its for debugging

    def sanitize_source(self, source):
        with open(source, 'r') as fin:
            root = ast.parse(fin.read())
        for node in root.body:
            if not isinstance(node, ast.ClassDef) and not isinstance(node, ast.FunctionDef):
                root.body.remove(node)
        return root

class CLIController(CementBaseController):
    class Meta:
        label = 'base'
        description = "Tool for encrypting multiple python source files into a single unit that can be run from the RUN utility."
        arguments = [
            (['-e', '--entry'], dict(action='store', dest='entry', help='Specify file as application entry point')),
            (['-s', '--source'], dict(action='store', dest='source', nargs='*', help='Space seperated list of source files to be encrypted')),
            (['-p', '--password'], dict(action='store', dest='password', help='Password/Secret used to encrypt source files')),
            (['-o', '--output'], dict(action='store', dest='output', default='output.sec', help="Specify output path and filename")),
            (['-t', '--type'], dict(action='store', dest='storage_type', choices=['a','r'], default='a', help="Specify how code should be stored in the encrypted file. For AST (compatability) use 'a'. For raw code (file size) use 'r'")),
            (['-c', '--compress'], dict(action='store_true', dest='compress', help="Compress output format for reduced filesize (zlib)")),
            (['-d', '--debugOutput'], dict(action='store_true', dest='debug', help="Prints the approximate source code that will be placed into the runnable unit (before encryption)"))
        ]

    @expose(hide=True)
    def default(self):
        if self.app.pargs.entry and self.app.pargs.source and self.app.pargs.password:
            se = SourceEncryptor()
            (iv, enc_source) = se.merge_and_encrypt(self.app.pargs.source, self.app.pargs.entry, self.app.pargs.password, self.app.pargs.storage_type, self.app.pargs.compress, self.app.pargs.debug)
            with open(self.app.pargs.output,'wb') as fout:
                if self.app.pargs.compress:
                    fout.write('c')                          #compressed
                else:
                    fout.write('u')                          #uncompressed
                fout.write(self.app.pargs.storage_type)      #storage_type code
                fout.write(iv)                               #initialization vector
                fout.write(enc_source)                       #encrypted source
            
class CLIApplication(CementApp):
    class Meta:
        label = "enc"
        base_controller = "base"
        handlers = [CLIController]

if __name__ == "__main__":
    with CLIApplication() as app:
        app.run()