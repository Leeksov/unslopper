"""Build the SDK-independent C++ matcher and compare synthetic fixtures."""
import shutil,subprocess,tempfile,unittest
from pathlib import Path
import test_arxan_analysis as fixtures
ROOT=Path(__file__).resolve().parents[1]

@unittest.skipUnless(shutil.which('c++'),'C++17 compiler unavailable')
class NativeMatcherTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory();cls.directory=Path(cls.temp.name);cls.driver=cls.directory/'native'
        subprocess.run(['c++','-std=c++17','-Wall','-Wextra','-Werror','-I',str(ROOT/'src/passes'),
            str(ROOT/'tests/arxan_native_patterns.cpp'),str(ROOT/'src/passes/arxan_patterns.cpp'),'-o',str(cls.driver)],check=True)
    @classmethod
    def tearDownClass(cls):cls.temp.cleanup()
    def test_cpp_fixtures(self):subprocess.run([str(self.driver)],check=True,capture_output=True)
    def test_python_cpp_parity(self):
        for index,image in enumerate([fixtures.multiply(),fixtures.zero(),fixtures.zero(True),fixtures.zero(True,True),fixtures.cancelled()]):
            path=self.directory/f'fixture{index}';path.write_bytes(image.data)
            args=[str(self.driver),str(path),hex(image.text[0]),hex(image.text[1]),f'{image.text[0]},0,{len(image.data)},{3 if image.writable else 5}']
            actual=[]
            for line in subprocess.check_output(args,text=True).splitlines():
                site,target,start,kind=line.split();actual.append((int(site,16),int(target,16),int(start,16),kind))
            expected=[(int(r['ea'],16),int(r['target'],16),int(r['window']['ea'],16),r['pattern']) for r in fixtures.m.analyze(image)['records']]
            self.assertEqual(actual,expected)

if __name__=='__main__':unittest.main()
