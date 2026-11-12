# WireScope - Checks that what goes to GitHub is in English before it is published: code, comments,
# scripts, project files, README and file names. The maintainer works in Polish, so it looks for
# Polish letters and for common Polish words written without them.
#
# Not checked, on purpose: the translations (src/resources/language/*.lng and the Polish column of
# tools/strings.py), files the repository ignores, and this script, whose word list is Polish.
# Symbols such as arrows are fine; so are Polish letters used as an example in an English sentence
# (listed in ALLOWED).
#   python tools/check-english.py        exit 0 = clean, 1 = something to look at
import ast
import os
import re
import sys

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
SKIP_DIRS = {'.git', '.vs', 'bin', 'obj', 'x64', 'driver', 'rsc', 'priv', 'release'}
SKIP_FILES = {'tools/check-english.py', 'od_marka.txt', 'sonnet.txt'}
TEXT_EXT = {'.cpp', '.h', '.rc', '.manifest', '.ps1', '.psm1', '.py', '.md', '.txt', '.vcxproj', '.filters', '.slnx', '.json',
            '.sh', '.gitignore', '.gitattributes'}
LETTERS = re.compile('[ąćęłńóśźżĄĆĘŁŃÓŚŹŻ]')
WORDS = re.compile(r'(?<![A-Za-z_])(nie|jest|oraz|albo|lub|dla|przez|jako|tylko|teraz|gdy|jesli|jezeli|plik\w*|sterownik\w*|zapor\w*|'
                   r'regul[ayeo]\w*|pakiet\w*|polacz\w*|wylacz\w*|wlacz\w*|zmien\w*|uruchom\w*|blad\w*|bledu|ustaw\w*|sieci|ktor\w+|'
                   r'moze|wiecej|wszystk\w*|narzedz\w*|sprawdz\w*|przyklad\w*|uwaga|zrob\w*|tutaj|jezyk\w*|okno|przycisk\w*|strona|'
                   r'procesy|liczenie|zablokuj|ogranicz|symuluj|gniazd\w*|podpis\w*|wyzeruj)(?![A-Za-z_])', re.IGNORECASE)
ALLOWED = {
    ('src/support/Text.h', '"Ł" -> "ł"'),  # the case-folding example names the letters
    ('README.md', 'Marek Wesołowski'),     # the author's name
    ('LICENSE.md', 'Marek Wesołowski'),
    ('src/resources/app.rc', 'Marek Wesołowski'),
}
findings = 0


def report(rel, number, line, why):
    global findings
    if any(rel == f and snippet in line for f, snippet in ALLOWED):
        return
    findings += 1
    print(f'{rel}:{number}: [{why}] {line.strip()[:160]}')


def check(rel, number, text, what):
    if LETTERS.search(text):
        report(rel, number, text, f'{what}: Polish letters')
    elif match := WORDS.search(text):
        report(rel, number, text, f'{what}: "{match.group(0)}"')


def check_string_table(path, rel):
    # Comments and the English column only; the Polish column is the translation.
    source = open(path, encoding='utf-8').read()
    for number, line in enumerate(source.splitlines(), 1):
        if line.lstrip().startswith('#'):
            check(rel, number, line, 'comment')
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Call) and getattr(node.func, 'id', '') in ('T', 'G'):
            texts = [a.value for a in node.args if isinstance(a, ast.Constant) and isinstance(a.value, str)]
            english = texts[1] if node.func.id == 'T' and len(texts) > 1 else (texts[0] if texts else '')
            check(rel, node.lineno, english, 'English text')


for base, dirs, files in os.walk(ROOT):
    dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
    for name in sorted(dirs + files):
        rel = os.path.relpath(os.path.join(base, name), ROOT).replace('\\', '/')
        if rel not in SKIP_FILES:
            check(rel, 0, os.path.splitext(name)[0].replace('-', ' ').replace('_', ' '), 'file name')
    for name in sorted(files):
        path = os.path.join(base, name)
        rel = os.path.relpath(path, ROOT).replace('\\', '/')
        ext = os.path.splitext(name)[1].lower() or name.lower()
        if rel in SKIP_FILES or rel.startswith('src/resources/language/') or ext not in TEXT_EXT:
            continue
        if rel == 'tools/strings.py':
            check_string_table(path, rel)
            continue
        try:
            text = open(path, encoding='utf-8-sig').read()
        except UnicodeDecodeError:
            report(rel, 0, '', 'not UTF-8')
            continue
        for number, line in enumerate(text.splitlines(), 1):
            check(rel, number, line, 'text')

print('clean' if findings == 0 else f'{findings} finding(s)')
sys.exit(1 if findings else 0)
