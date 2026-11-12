# WireScope - Rewrites the item groups of WireScope.vcxproj and WireScope.vcxproj.filters from the
# files under src\, so a source file added or removed is never forgotten in the project.
# Everything outside the item groups (settings, toolset, imports) is left as it is.
#   python tools/sync-project.py
import glob
import os

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
ORDER = ['app', 'core', 'gui', 'support', 'resources']
RC = 'src\\resources\\app.rc'
MANIFEST = 'src\\resources\\app.manifest'
EN = 'src\\resources\\lang\\en.rc'
BMP = 'src\\resources\\WireScope.bmp'


def files(pattern):
    found = [os.path.relpath(p, ROOT) for p in glob.glob(os.path.join(ROOT, 'src', '*', pattern))]
    return sorted(found, key=lambda p: (ORDER.index(p.split(os.sep)[1]), p.lower()))


def rewrite(name, start_marker, end_marker, groups):
    path = os.path.join(ROOT, name)
    text = open(path, encoding='utf-8').read().replace('\r\n', '\n')
    start = text.index(start_marker)
    end = text.index(end_marker) if end_marker else len(text)
    text = text[:start] + '\n'.join(groups) + '\n' + (text[end:] if end_marker else '')
    open(path, 'w', encoding='utf-8', newline='\r\n').write(text)
    data = open(path, 'rb').read()
    assert not any(c < 9 or c in (11, 12) or 13 < c < 32 for c in data), f'{name}: control characters'


cpp, hdr = files('*.cpp'), files('*.h')
lng = sorted(os.path.relpath(p, ROOT) for p in glob.glob(os.path.join(ROOT, 'src', 'resources', 'language', '*.lng')))
folder = lambda q: q.split(os.sep)[1]

project = (['  <ItemGroup>'] + [f'    <ClCompile Include="{p}" />' for p in cpp] + ['  </ItemGroup>', '  <ItemGroup>'] +
           [f'    <ClInclude Include="{p}" />' for p in hdr] +
           ['  </ItemGroup>', '  <ItemGroup>', f'    <ResourceCompile Include="{RC}" />', '  </ItemGroup>', '  <ItemGroup>',
            f'    <None Include="{MANIFEST}" />', f'    <None Include="{EN}" />', f'    <Image Include="{BMP}" />', '  </ItemGroup>', '  <ItemGroup>',
            '    <!-- Language files are not compiled in: they are copied next to the executable (bin\\language). -->'] +
           [f'    <CopyFileToFolders Include="{p}"><DestinationFolders>$(OutDir)language</DestinationFolders></CopyFileToFolders>' for p in lng] +
           ['  </ItemGroup>'])
rewrite('WireScope.vcxproj', '  <ItemGroup>\n    <ClCompile', '  <Import Project="$(VCTargetsPath)\\Microsoft.Cpp.targets" />', project)

filters = (['  <ItemGroup>'] + [f'    <ClCompile Include="{q}"><Filter>{folder(q)}</Filter></ClCompile>' for q in cpp] +
           ['  </ItemGroup>', '  <ItemGroup>'] + [f'    <ClInclude Include="{q}"><Filter>{folder(q)}</Filter></ClInclude>' for q in hdr] +
           ['  </ItemGroup>', '  <ItemGroup>', f'    <ResourceCompile Include="{RC}"><Filter>resources</Filter></ResourceCompile>',
            '  </ItemGroup>', '  <ItemGroup>', f'    <None Include="{MANIFEST}"><Filter>resources</Filter></None>',
            f'    <None Include="{EN}"><Filter>resources</Filter></None>', f'    <Image Include="{BMP}"><Filter>resources</Filter></Image>', '  </ItemGroup>', '  <ItemGroup>'] +
           [f'    <CopyFileToFolders Include="{q}"><Filter>resources</Filter></CopyFileToFolders>' for q in lng] +
           ['  </ItemGroup>', '</Project>'])
rewrite('WireScope.vcxproj.filters', '  <ItemGroup>\n    <ClCompile', None, filters)
print(len(cpp), 'sources,', len(hdr), 'headers,', len(lng), 'language files')
