#!/usr/bin/env python3
"""
Асинхронный JS Vulnerability Scanner
Обнаруживает уязвимости в JavaScript коде с использованием async/await
"""

import re
import os
import json
import argparse
import asyncio
import aiofiles
from pathlib import Path
from typing import List, Dict, Set, Tuple, Optional
from concurrent.futures import ThreadPoolExecutor
import aiohttp
import warnings
warnings.filterwarnings('ignore')

class AsyncJSVulnerabilityScanner:
    def __init__(self, max_workers: int = 10):
        self.max_workers = max_workers
        self.semaphore = asyncio.Semaphore(max_workers)
        self.patterns = {
            'sql_injection': [
                r'(?i)SELECT.*FROM.*\+.*(req\.|param|query|body|input)',
                r'(?i)INSERT.*\+.*(req\.|param|query|body|input)',
                r'(?i)UPDATE.*\+.*(req\.|param|query|body|input)',
                r'(?i)query\(.*\+.*(req\.|param|query|body|input)',
                r'(?i)execute\(.*\+.*(req\.|param|query|body|input)',
                r'(?i)`SELECT.*\$\{.*\}`',
                r'(?i)`INSERT.*\$\{.*\}`',
                r'(?i)`UPDATE.*\$\{.*\}`'
            ],
            'xss': [
                r'innerHTML\s*=\s*.*(req\.|param|query|body|input)',
                r'document\.write\(.*(req\.|param|query|body|input)',
                r'\.html\(.*(req\.|param|query|body|input)',
                r'\.append\(.*(req\.|param|query|body|input)',
                r'response\.send\(.*(req\.|param|query|body|input)',
                r'response\.write\(.*(req\.|param|query|body|input)',
                r'\.replaceWith\(.*(req\.|param|query|body|input)'
            ],
            'command_injection': [
                r'child_process\.exec\(.*(req\.|param|query|body|input)',
                r'child_process\.spawn\(.*(req\.|param|query|body|input)',
                r'exec\(.*(req\.|param|query|body|input)',
                r'spawn\(.*(req\.|param|query|body|input)',
                r'execSync\(.*(req\.|param|query|body|input)',
                r'`.*\$\{.*(req\.|param|query|body|input).*\}`'
            ],
            'path_traversal': [
                r'fs\.readFile\(.*(req\.|param|query|body|input)',
                r'fs\.writeFile\(.*(req\.|param|query|body|input)',
                r'require\(.*(req\.|param|query|body|input)',
                r'path\.join\(.*(req\.|param|query|body|input)',
                r'\.\.\/.*(req\.|param|query|body|input)',
                r'__dirname\s*\+\s*(req\.|param|query|body|input)'
            ],
            'hardcoded_secrets': [
                r'(?i)password\s*[:=]\s*[\'"][^\'"]{8,}[\'"]',
                r'(?i)api[_-]?key\s*[:=]\s*[\'"][^\'"]{10,}[\'"]',
                r'(?i)secret\s*[:=]\s*[\'"][^\'"]{8,}[\'"]',
                r'(?i)token\s*[:=]\s*[\'"][^\'"]{10,}[\'"]',
                r'(?i)auth\s*[:=]\s*[\'"][^\'"]{8,}[\'"]',
                r'(?i)jwt\s*[:=]\s*[\'"][^\'"]{10,}[\'"]'
            ],
            'eval_usage': [
                r'eval\(.*(req\.|param|query|body|input)',
                r'Function\(.*(req\.|param|query|body|input)',
                r'setTimeout\(.*(req\.|param|query|body|input).*\)',
                r'setInterval\(.*(req\.|param|query|body|input).*\)',
                r'new Function\(.*(req\.|param|query|body|input)'
            ],
            'insecure_dependencies': [
                r'require\([\'"](http:|https:)[\'"]\)',
                r'from\s+[\'"](http:|https:)[\'"]',
                r'import\s+.*from\s+[\'"](http:|https:)[\'"]',
                r'require\([\'"]\.\.\/\.\.\/[^\'"]+[\'"]\)'
            ],
            'cors_misconfig': [
                r'Access-Control-Allow-Origin\s*:\s*[\'"]\*[\'"]',
                r'res\.setHeader\([\'"]Access-Control-Allow-Origin[\'"],\s*[\'"]\*[\'"]\)',
                r'origin:\s*true',
                r'credentials:\s*false.*origin:\s*true'
            ]
        }
        
        self.severity_levels = {
            'sql_injection': 'HIGH',
            'xss': 'HIGH',
            'command_injection': 'CRITICAL',
            'path_traversal': 'HIGH',
            'hardcoded_secrets': 'MEDIUM',
            'eval_usage': 'HIGH',
            'insecure_dependencies': 'MEDIUM',
            'cors_misconfig': 'MEDIUM'
        }

        self.compiled_patterns = {
            vuln_type: [re.compile(pattern, re.IGNORECASE | re.MULTILINE) 
                       for pattern in patterns]
            for vuln_type, patterns in self.patterns.items()
        }

    async def scan_file(self, file_path: str) -> List[Dict]:
        """Асинхронно сканирует один JS файл на уязвимости"""
        vulnerabilities = []
        
        try:
            async with self.semaphore:
                async with aiofiles.open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
                    content = await file.read()
                    lines = content.split('\n')
                    
                    for vuln_type, patterns in self.compiled_patterns.items():
                        for pattern in patterns:
                            matches = pattern.finditer(content)
                            for match in matches:
                                line_number = content[:match.start()].count('\n') + 1
                                line_content = lines[line_number - 1].strip() if line_number <= len(lines) else ''
                                
                                vulnerabilities.append({
                                    'file': file_path,
                                    'line': line_number,
                                    'type': vuln_type,
                                    'severity': self.severity_levels.get(vuln_type, 'UNKNOWN'),
                                    'pattern': pattern.pattern,
                                    'code_snippet': self._truncate_code(line_content),
                                    'description': self.get_vuln_description(vuln_type),
                                    'match': match.group(0)[:100] + '...' if len(match.group(0)) > 100 else match.group(0)
                                })
        
        except Exception as e:
            print(f"Ошибка при сканировании файла {file_path}: {e}")
        
        return vulnerabilities

    def _truncate_code(self, code: str, max_length: int = 150) -> str:
        """Обрезает длинные строки кода"""
        return code[:max_length] + '...' if len(code) > max_length else code

    async def scan_directory(self, directory: str) -> List[Dict]:
        """Асинхронно рекурсивно сканирует директорию с JS файлами"""
        all_vulnerabilities = []
        js_files = await self._find_js_files(directory)
        
        tasks = [self.scan_file(file_path) for file_path in js_files]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, Exception):
                print(f"Ошибка при сканировании: {result}")
            elif isinstance(result, list):
                all_vulnerabilities.extend(result)
        
        return all_vulnerabilities

    async def _find_js_files(self, directory: str) -> List[str]:
        """Асинхронно находит все JS файлы в директории"""
        js_files = []
        js_extensions = {'.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'}
        
        async def _walk_dir(path: Path):
            try:
                for entry in path.iterdir():
                    if entry.is_dir():
                        if entry.name not in {'node_modules', '.git', 'dist', 'build'}:
                            await _walk_dir(entry)
                    elif entry.suffix in js_extensions:
                        js_files.append(str(entry))
            except Exception as e:
                print(f"Ошибка при обходе директории {path}: {e}")
        
        await _walk_dir(Path(directory))
        return js_files

    def get_vuln_description(self, vuln_type: str) -> str:
        """Возвращает описание уязвимости"""
        descriptions = {
            'sql_injection': 'SQL injection - пользовательский ввод напрямую используется в SQL запросе',
            'xss': 'XSS уязвимость - пользовательский ввод выводится без санитизации',
            'command_injection': 'Command injection - пользовательский ввод используется в системных командах',
            'path_traversal': 'Path Traversal - пользовательский ввод используется в путях файлов',
            'hardcoded_secrets': 'Хардкодные секреты (пароли, API ключи) в коде',
            'eval_usage': 'Использование eval с пользовательским вводом',
            'insecure_dependencies': 'Зависимости из ненадежных источников',
            'cors_misconfig': 'Небезопасная CORS конфигурация'
        }
        return descriptions.get(vuln_type, 'Неизвестная уязвимость')

    def generate_report(self, vulnerabilities: List[Dict], output_format: str = 'text') -> str:
        """Генерирует отчет в различных форматах"""
        if output_format == 'json':
            return json.dumps(vulnerabilities, indent=2, ensure_ascii=False)
        elif output_format == 'csv':
            return self._generate_csv_report(vulnerabilities)
        else:
            return self._generate_text_report(vulnerabilities)

    def _generate_text_report(self, vulnerabilities: List[Dict]) -> str:
        """Генерирует текстовый отчет"""
        if not vulnerabilities:
            return "✅ Уязвимостей не найдено!"
        
        report = []
        for i, vuln in enumerate(vulnerabilities, 1):
            report.append(
                f"{i}. [{vuln['severity']}] {vuln['file']}:{vuln['line']}\n"
                f"   Тип: {vuln['type']}\n"
                f"   Описание: {vuln['description']}\n"
                f"   Найдено: {vuln['match']}\n"
                f"   Код: {vuln['code_snippet']}\n"
                f"{'-'*60}"
            )
        return '\n'.join(report)

    def _generate_csv_report(self, vulnerabilities: List[Dict]) -> str:
        """Генерирует CSV отчет"""
        if not vulnerabilities:
            return "file,line,type,severity,description"
        
        csv_lines = ["file,line,type,severity,description,match"]
        for vuln in vulnerabilities:
            csv_lines.append(
                f'"{vuln["file"]}",{vuln["line"]},{vuln["type"]},'
                f'{vuln["severity"]},"{vuln["description"]}","{vuln["match"]}"'
            )
        return '\n'.join(csv_lines)

    async def check_dependencies(self, directory: str) -> List[Dict]:
        """Проверяет зависимости package.json на уязвимости"""
        package_json_path = os.path.join(directory, 'package.json')
        if not os.path.exists(package_json_path):
            return []
        
        try:
            async with aiofiles.open(package_json_path, 'r') as f:
                content = await f.read()
                package_data = json.loads(content)
                
            dependencies = {**package_data.get('dependencies', {}), 
                          **package_data.get('devDependencies', {})}
            
            # Здесь можно добавить проверку через Snyk API или другие источники
            vulnerable_deps = []
            for dep, version in dependencies.items():
                # Простая проверка на известные проблемные пакеты
                if any(bad in dep for bad in ['test', 'example', 'malicious']):
                    vulnerable_deps.append({
                        'dependency': dep,
                        'version': version,
                        'issue': 'Подозрительное имя пакета',
                        'severity': 'MEDIUM'
                    })
            
            return vulnerable_deps
            
        except Exception as e:
            print(f"Ошибка при проверке зависимостей: {e}")
            return []

async def main():
    parser = argparse.ArgumentParser(description='Асинхронный сканер уязвимостей JavaScript кода')
    parser.add_argument('target', help='Файл или директория для сканирования')
    parser.add_argument('--output', '-o', help='Файл для сохранения отчета')
    parser.add_argument('--format', '-f', choices=['text', 'json', 'csv'], default='text', 
                       help='Формат отчета')
    parser.add_argument('--verbose', '-v', action='store_true', help='Подробный вывод')
    parser.add_argument('--workers', '-w', type=int, default=10, 
                       help='Количество одновременных workers')
    parser.add_argument('--check-deps', '-d', action='store_true', 
                       help='Проверить зависимости package.json')
    
    args = parser.parse_args()
    
    scanner = AsyncJSVulnerabilityScanner(max_workers=args.workers)
    
    start_time = asyncio.get_event_loop().time()
    
    if os.path.isfile(args.target):
        vulnerabilities = await scanner.scan_file(args.target)
        files_scanned = 1
    elif os.path.isdir(args.target):
        vulnerabilities = await scanner.scan_directory(args.target)
        files_scanned = len(await scanner._find_js_files(args.target))
    else:
        print(f"Ошибка: {args.target} не является файлом или директорией")
        return
    
    # Проверка зависимостей если нужно
    dependency_issues = []
    if args.check_deps and os.path.isdir(args.target):
        dependency_issues = await scanner.check_dependencies(args.target)
    
    end_time = asyncio.get_event_loop().time()
    scan_duration = end_time - start_time
    
    # Генерация отчета
    report = scanner.generate_report(vulnerabilities, args.format)
    
    if args.output:
        async with aiofiles.open(args.output, 'w', encoding='utf-8') as f:
            await f.write(report)
        print(f"Отчет сохранен в: {args.output}")
    else:
        print(report)
    
    # Вывод статистики
    if args.verbose:
        print(f"\n📊 Статистика сканирования:")
        print(f"   Файлов проверено: {files_scanned}")
        print(f"   Уязвимостей найдено: {len(vulnerabilities)}")
        print(f"   Проблем с зависимостями: {len(dependency_issues)}")
        print(f"   Время сканирования: {scan_duration:.2f} секунд")
        
        severity_count = {}
        for vuln in vulnerabilities:
            severity = vuln['severity']
            severity_count[severity] = severity_count.get(severity, 0) + 1
        
        print(f"\n📈 Распределение по severity:")
        for severity, count in severity_count.items():
            print(f"   {severity}: {count}")
        
        if dependency_issues:
            print(f"\n⚠️  Проблемы с зависимостями:")
            for issue in dependency_issues:
                print(f"   {issue['dependency']}@{issue['version']}: {issue['issue']}")

if __name__ == '__main__':
    asyncio.run(main())