#!/usr/bin/env python
import collections
import json
import logging
import pprint
import sys
from pathlib import Path

import utils
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from elftools.common.exceptions import ELFError, ELFParseError

logging.basicConfig(level=logging.DEBUG)


def _parse_jsons(json_folder):
    """Loads all json files from json_folder and returns them in a list."""
    jsons = utils.find('*.json', json_folder)
    data = []

    for json_path in jsons:
        logging.debug(f'Loading file {json_path}')
        with open(json_path, 'r') as f:
            json_data = json.load(f)

        data.append(json_data)

    return data


def _get_libs_per_app(data):
    """Removes architecture separation from data."""
    result = {}
    for app in data:
        all_arch_libs = [lib for sublist in app['libs'].values() for lib in sublist]
        result[app['package']] = list(dict.fromkeys(all_arch_libs))

    assert len(result) == len(data)
    return result


def _get_all_libs(data):
    """Returns list of all library names."""
    libs = _get_libs_per_app(data)

    return list(dict.fromkeys([l for sublist in libs.values() for l in sublist]))


def _get_exports_per_lib(lib_name, libs_dir='libs'):
    """Returns a list of all exported symbols given the lib_name."""
    symbols = []
    for lib in utils.find(lib_name, libs_dir):
        with lib.open('rb') as fptr:
            try:
                elf = ELFFile(fptr)
                for section in elf.iter_sections():
                    if isinstance(section, SymbolTableSection):
                        symbols.extend([symbol.name for symbol in list(section.iter_symbols())])
            except ELFParseError:
                logging.warning(f'Failed to parse {lib}')
            except ELFError:
                logging.warning(f'Failed to load {lib}')

    return list(set(symbols))


def _filter_JNI_exports(symbols, include_java=True, include_onload=True):
    """Removes symbols from the given list if they are not JNI-related."""
    result = []
    for symbol in symbols:
        if include_onload and 'JNI_OnLoad' in symbol:
            result.append(symbol)
        elif include_java and symbol.startswith('Java_'):
            result.append(symbol)
    return result


def _library_match(lib, tags):
    """Returns True, if the library matches the given tags."""
    # Check the library name
    if any([tag in lib.lower() for tag in tags]):
        return True

    # Check every symbol
    symbols = _get_exports_per_lib(lib)
    for symbol in symbols:
        if any([tag in symbol.lower() for tag in tags]):
            return True

    return False


def misc_analysis(data):
    """Miscellaneous analyses."""
    logging.info('* Overall apps with x86 native libs:')
    x86_data = [apk for apk in data if 'x86' in apk['libs'].keys()]
    logging.info(len(x86_data))

    logging.info('* The 10 smallest apps:')
    x86_data_sorted = sorted(x86_data, key=lambda a: a['size'])
    for i in range(10):
        logging.info(x86_data_sorted[i]['filename'])

    logging.info('* Info about the 10 smallest apps:')
    smallest = x86_data_sorted[:10]
    pprint.pprint(smallest)

    logging.info('* Library usage:')
    all_lib_names = [x for sublist in [p['libs']['x86'] for p in x86_data] for x in sublist]
    lib_usage = collections.Counter(all_lib_names)
    pprint.pprint(lib_usage)


def _interactive_library_classification(data):
    """Presents lib info and records library tags."""
    with Path('./domains/new/all_lib_names.txt').open() as fptr:
        unclassified_libs = fptr.read().strip().split('\n')

    with Path('./log.txt').open() as fptr:
        log = fptr.read()

    for lib in unclassified_libs:
        if lib in log:
            continue
        print('\n'*4 + lib + '\n')
        for s in sorted(_filter_JNI_exports(_get_exports_per_lib(lib))):
            print(s)
        tag = input()
        if tag:
            with Path('log.txt').open('a') as fptr:
                fptr.write(lib + ': ' + tag + '\n')


def domain_analysis(data):
    """Prints the category matches for all libraries."""
    tags = {'image' : ['jpg', 'jpeg', 'gif', 'png', 'heif', 'image', 'yuv'],
            'pdf' : ['pdf'],
            'crypto' : ['crypto', 'encrypt', 'decrypt', 'conceal', 'tls', 'ssl'],
            'crypto_small' : ['crypto', 'encrypt', 'decrypt', 'conceal'],
            'tls_ssl' : ['tls', 'ssl'],
            'codec_large' : ['codec', 'encode', 'decode', '7z', 'zstd', 'compress'],
            'codec' : ['codec', 'encode', 'decode', 'zstd', 'compress'],
            '7z' : ['7z'],
            'crash' : ['crash'],
            'av' : ['ffmpeg', 'opus', 'video', 'audio'],
            'filter' : ['filter'],
            'sql' : ['sql']}

    jni_libs = _get_all_libs(data)

    counts = {}
    for category in tags:
        counts[category] = 0

    for lib in jni_libs:
        logging.debug(lib)
        for category, tag_list in tags.items():
            if _library_match(lib, tag_list):
                counts[category] += 1

        logging.debug(counts)
    logging.info(counts)


def architecture_analysis(data, libs_dir='libs'):
    """Prints the distribution of architectures."""
    jni_libs = _get_all_libs(data)

    only_arm = 0
    only_x86 = 0
    both = 0
    none = 0
    for lib_name in jni_libs:
        x86 = False
        arm = False
        for lib in utils.find(lib_name, libs_dir):
            if lib.match('*/x86/*') or lib.match('*/x86_64/*'):
                x86 = True
            elif lib.match('*/armeabi-v7a/*') or lib.match('*/arm64-v8a/*') or lib.match('*/armeabi/*'):
                arm = True
            else:
                arch = lib.parent.name
                logging.warning(f'unmatched arch: {arch}')
        if arm and not x86:
            only_arm += 1
        if x86 and not arm:
            only_x86 += 1
        if arm and x86:
            both += 1
        if not arm and not x86:
            none += 1

        logging.debug(f'status: {only_arm}/{only_x86}/{both}/{none}')
    logging.info(f'status: {only_arm}/{only_x86}/{both}/{none}')


def library_distribution_analysis(data):
    """Prints some distribution of libs and apps."""
    libs = _get_libs_per_app(data)
    all_lib_names = _get_all_libs(data)

    # Top used apps
    num_apps = []
    for lib in sorted(list(all_lib_names)):
        x = lib
        app_count = len([l for l in list(libs.values()) if x in l])
        num_apps.append(app_count)
        if app_count > 13:
            print(f'{app_count}: {lib}')

    # Number of apps in which each library is used
    print('numbers of apks in which a library is used: number of libraries')
    for j in range(1, max(num_apps)+1):
        print(str(j) + ': ' + str(len([i for i in num_apps if i == j])))

    print()

    # Number of libs that each app uses
    num_libs = [len(lib) for lib in libs.values()]

    print('number of libs that an apk uses: number of apks')
    for j in range(1, max(num_libs)+1):
        print(str(j) + ': ' + str(len([i for i in num_libs if i == j])))


def interface_analysis(data):
    """Print number of JNI_OnLoad vs Java_ libraries."""

    onload_and_java = 0
    onload_libs = []
    java_libs = []
    for i, lib_name in enumerate(_get_all_libs(data)):
        exports = _get_exports_per_lib(lib_name)

        onload_exports = _filter_JNI_exports(exports, include_java=False)
        java_exports = _filter_JNI_exports(exports, include_onload=False)

        if onload_exports:
            onload_libs.append(lib_name)

        if java_exports:
            java_libs.append(lib_name)

            if onload_exports:
                onload_and_java += 1

        logging.info(f'{len(onload_libs)}/{len(java_libs)}/{onload_and_java}/{i}')
    logging.info(f'{len(onload_libs)}/{len(java_libs)}/{onload_and_java}/{i}')


def start_analyses(data):
    """Runs the different analyses."""
    domain_analysis(data)

    architecture_analysis(data)

    library_distribution_analysis(data)

    interface_analysis(data)

    import IPython; IPython.embed()


def main():
    """Parses cmdline parameter and executes _parse_jsons."""
    if len(sys.argv) != 2:
        print(f'Usage: {sys.argv[0]} <json_folder>')
        sys.exit()

    all_jsons = _parse_jsons(sys.argv[1])

    start_analyses(all_jsons)

if __name__ == '__main__':
    main()
