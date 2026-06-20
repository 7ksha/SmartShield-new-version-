
class Module(object):
    name = ''
    description = 'Template abstract originals'
    output = []

    def __init__(self):
        pass

    def usage(self):
        print('Usage')

    def help(self):
        print('Help')

    def run(self):
        try:
            print('test')
        except Exception as e:
            print('error')
