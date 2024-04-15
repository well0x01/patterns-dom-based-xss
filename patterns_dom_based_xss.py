import re
import requests

import re

def encontrar_xss(source_code):
    highlighted = []
    sources = r'''\b(?:document\.(URL|documentURI|URLUnencoded|baseURI|cookie|referrer)|location\.(href|search|hash|pathname)|window\.name|history\.(pushState|replaceState)(local|session)Storage)\b'''
    sinks = r'''\b(?:eval|evaluate|execCommand|assign|navigate|getResponseHeaderopen|showModalDialog|Function|set(Timeout|Interval|Immediate)|execScript|crypto.generateCRMFRequest|ScriptElement\.(src|text|textContent|innerText)|.*?\.onEventName|document\.(write|writeln)|.*?\.innerHTML|Range\.createContextualFragment|(document|window)\.location)\b'''
    scripts = re.findall(r'(?i)(?s)<script[^>]*>(.*?)</script>', source_code)
    sink_found, source_found = False, False
    for script in scripts:
        script = script.split('\n')
        num = 1
        all_controlled_variables = set()
        try:
            for line in script:
                parts = line.split('var ')
                controlled_variables = set()
                if len(parts) > 1:
                    for part in parts:
                        for controlled_variable in all_controlled_variables:
                            if controlled_variable in part:
                                controlled_variables.add(re.search(r'[a-zA-Z$_][a-zA-Z0-9$_]+', part).group().replace('$', '\$'))
                pattern = re.finditer(sources, line)
                for grp in pattern:
                    if grp:
                        source = line[grp.start():grp.end()].replace(' ', '')
                        if source:
                            if len(parts) > 1:
                               for part in parts:
                                    if source in part:
                                        controlled_variables.add(re.search(r'[a-zA-Z$_][a-zA-Z0-9$_]+', part).group().replace('$', '\$'))
                            line = line.replace(source, '\033[33m' + source + '\033[0m')
                for controlled_variable in controlled_variables:
                    all_controlled_variables.add(controlled_variable)
                for controlled_variable in all_controlled_variables:
                    matches = list(filter(None, re.findall(r'\b%s\b' % controlled_variable, line)))
                    if matches:
                        source_found = True
                        line = re.sub(r'\b%s\b' % controlled_variable, '\033[33m' + controlled_variable + '\033[0m', line)
                pattern = re.finditer(sinks, line)
                for grp in pattern:
                    if grp:
                        sink = line[grp.start():grp.end()].replace(' ', '')
                        if sink:
                            line = line.replace(sink, '\033[31m' + sink + '\033[0m')
                            sink_found = True
                if line.strip() and line != script[num]:
                    highlighted.append('%-3s %s' % (str(num), line.lstrip(' ')))
                num += 1
        except MemoryError:
            pass
    if sink_found or source_found:
        return highlighted
    else:
        return []


def main():
    url = input("Digite a URL para analisar DOM-XSS: ")
    try:
        response = requests.get(url)
        if response.ok:
            source_code = response.text
            resultados = encontrar_xss(source_code)
            if resultados:
                print("Padrões de DOM-XSS encontrados no código-fonte:")
                for linha in resultados:
                    print(linha)
            else:
                print("Nenhum padrão de DOM-XSS encontrado no código-fonte.")
        else:
            print("Falha ao recuperar o conteúdo da página.")
    except Exception as e:
        print(f"Ocorreu um erro: {e}")

if __name__ == "__main__":
    main()
