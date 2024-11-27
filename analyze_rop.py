import re
import argparse
from collections import defaultdict
import sys

instruction_descriptions = {
    'aam': 'Ajuste ASCII después de Multiplicar.',
    'adc': 'Suma con acarreo.',
    'aas': 'Ajuste ASCII AL después de una Sustracción.',
    'add': 'Adición.',
    'and': 'AND lógico.',
    'arpl': 'Ajustar el Nivel de Privilegios del Solicitante.',
    'call': 'Llamar a un Procedimiento.',
    'cld': 'Borrar la Bandera de Dirección.',
    'dec': 'Decremento.',
    'inc': 'Incremento.',
    'jmp': 'Saltar a un procedimiento.',
    'lea': 'Cargar Dirección Efectiva.',
    'leave': 'Salir de un procedimiento.',
    'mov': 'Mover datos.',
    'movzx': 'Mover con Extensión a Cero.',
    'nop': 'No Operación.',
    'or': 'OR lógico.',
    'pop': 'Extraer valor de la pila.',
    'push': 'Insertar valor en la pila.',
    'retn': 'Retornar de un procedimiento.',
    'sar': 'Desplazamiento Aritmético a la Derecha.',
    'sub': 'Sustracción.',
    'xor': 'XOR lógico.',
    'xchg': 'Intercambiar los valores de dos registros.',
    'ret': 'Retornar de un procedimiento.',
    'retn': 'Retornar de un procedimiento con offset.',
    'pushad': 'Insertar todos los registros en la pila.',
    'popad': 'Extraer todos los registros de la pila.',
    'pushfd': 'Insertar las banderas en la pila.',
    'popfd': 'Extraer las banderas de la pila.',
    # agregar los que sea necesario 
}


gadget_categories = {
    'OPERACIONES LÓGICAS': ['and', 'or', 'xor'],
    'MANIPULACIÓN DE REGISTROS': ['mov', 'lea', 'push', 'pop', 'movzx', 'xchg', 'pushad', 'popad', 'pushfd', 'popfd'],
    'OPERACIONES ARITMÉTICAS': ['add', 'sub', 'inc', 'dec', 'adc', 'sar', 'aam', 'aas'],
    'CONTROL DE FLUJO': ['jmp', 'call', 'ret', 'retn'],
    'OPERACIONES DE PILA': ['push', 'pop', 'pushad', 'popad', 'pushfd', 'popfd'],
    'OPERACIONES DE AJUSTE': ['aam', 'aas', 'arpl'],
    'BANDERA DE DIRECCIÓN': ['cld'],
}

def parse_rop_file(file_path, min_instr=2, max_instr=5):
    """
    Parsea el archivo rop.txt y extrae los gadgets que tienen entre min_instr y max_instr instrucciones.
    Maneja gadgets que terminan con '; (X found)' y aquellos que no lo hacen.
    """
    gadgets = []
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            for line in file:
                line = line.strip()
                if not line:
                    continue  
                
                parts = line.split(':', 1)
                if len(parts) != 2:
                    continue  
                address = parts[0].strip()
                instructions_part = parts[1].strip()
                
                instructions_clean_match = re.match(r'^(.*?);\s*\(\d+\s+found\)$', instructions_part)
                if instructions_clean_match:
                    instructions_clean = instructions_clean_match.group(1)
                else:
                    
                    instructions_clean = instructions_part
                
                instructions = [instr.strip() for instr in instructions_clean.split(';') if instr.strip()]
                
                if min_instr <= len(instructions) <= max_instr:
                    gadgets.append({'address': address, 'instructions': instructions, 'full_line': line})
    except FileNotFoundError:
        print(f"Error: El archivo '{file_path}' no se encontró.")
        sys.exit(1)
    except Exception as e:
        print(f"Error al leer el archivo '{file_path}': {e}")
        sys.exit(1)
    return gadgets

def extract_mnemonic(instruction):
    """
    Maneja instrucciones con comas y múltiples espacios.
    """
    tokens = re.split(r'[ ,]+', instruction)
    return tokens[0].lower() if tokens else ''

def categorize_gadget(gadget):
    """
    Categoriza un gadget basado en sus instrucciones.
    """
    categories = set()
    for instr in gadget['instructions']:
        mnemonic = extract_mnemonic(instr)
        for category, keywords in gadget_categories.items():
            if mnemonic in keywords:
                categories.add(category)
    if not categories:
        categories.add('OTRAS')
    return categories

def describe_gadgets(gadgets, output_stream):
    """
    Imprime la descripción detallada de cada gadget, incluyendo usos en ROP.
    """
    for gadget in gadgets:
        categories = categorize_gadget(gadget)
        categories_str = ', '.join(categories)
        output_stream.write(f"Gadget: {gadget['full_line']}\n")
        output_stream.write(f"Categorías: {categories_str}\n")
        output_stream.write("Descripción de Instrucciones y Usos:\n")
        for instr in gadget['instructions']:
            mnemonic = extract_mnemonic(instr)
            description = instruction_descriptions.get(mnemonic, 'Descripción no disponible.')
            
            usage = ""
            if mnemonic in ['pop', 'popad', 'popfd']:
                usage = " - Utilizado para recuperar valores almacenados previamente en la pila."
            elif mnemonic in ['push', 'pushad', 'pushfd']:
                usage = " - Utilizado para almacenar valores en la pila, facilitando la manipulación de registros."
            elif mnemonic in ['xchg']:
                usage = " - Permite intercambiar valores entre registros, útil para pivotar la pila o reordenar registros."
            elif mnemonic in ['inc', 'dec']:
                usage = " - Modifica el valor de un registro, permitiendo ajustes dinámicos durante la ejecución del ROP chain."
            elif mnemonic in ['jmp', 'call']:
                usage = " - Controla el flujo de ejecución, permitiendo saltar a diferentes gadgets."
            elif mnemonic in ['ret', 'retn']:
                usage = " - Retorna a la dirección apuntada por la pila, facilitando el encadenamiento de gadgets."
            elif mnemonic in ['mov', 'movzx']:
                usage = " - Transfiere datos entre registros o memoria, esencial para preparar el estado de los registros."
            
            output_stream.write(f"  {instr} - {description}{usage}\n")
        output_stream.write("Posibles Usos en ROP:\n")
        output_stream.write(f"  Este gadget puede ser utilizado para:\n")
        for instr in gadget['instructions']:
            mnemonic = extract_mnemonic(instr)
            if mnemonic in ['pop', 'popad', 'popfd']:
                output_stream.write(f"    - Recuperar valores de registros desde la pila.\n")
            elif mnemonic in ['push', 'pushad', 'pushfd']:
                output_stream.write(f"    - Almacenar valores de registros en la pila.\n")
            elif mnemonic == 'xchg':
                output_stream.write(f"    - Pivotar la pila o reordenar registros para manipular el flujo de ejecución.\n")
            elif mnemonic in ['inc', 'dec']:
                output_stream.write(f"    - Ajustar dinámicamente los valores de registros durante la ejecución del ROP chain.\n")
            elif mnemonic in ['jmp', 'call']:
                output_stream.write(f"    - Controlar el flujo de ejecución para saltar a diferentes gadgets.\n")
            elif mnemonic in ['ret', 'retn']:
                output_stream.write(f"    - Encadenar gadgets al retornar a direcciones específicas en la pila.\n")
            elif mnemonic in ['mov', 'movzx']:
                output_stream.write(f"    - Preparar el estado de los registros moviendo datos necesarios para el ataque.\n")
            
        output_stream.write('-' * 80 + '\n')

def categorize_and_print(gadgets, output_stream):
    """
    Agrupa los gadgets por categorías y los imprime con encabezados más prominentes.
    """
    category_to_gadgets = defaultdict(list)
    for gadget in gadgets:
        categories = categorize_gadget(gadget)
        for category in categories:
            category_to_gadgets[category].append(gadget)
    
    for category in sorted(category_to_gadgets.keys()):
        
        output_stream.write(f"\n=== {category} ===\n")
        output_stream.write("=" * (len(category) + 6) + "\n")
        for gadget in category_to_gadgets[category]:
            output_stream.write(gadget['full_line'] + "\n")
        output_stream.write('-' * 80 + '\n')

def recomendar_gadgets(gadgets, criteria=None):
    """
    Recomienda gadgets basados en criterios específicos.
    """
    recomendaciones = []
    for gadget in gadgets:
        for instr in gadget['instructions']:
            if criteria:
                if criteria(instr.lower()):
                    recomendaciones.append(gadget)
                    break
            else:
                
                if instr.lower().startswith('pop '):
                    recomendaciones.append(gadget)
                    break
    return recomendaciones

def print_recomendaciones(recomendaciones, description, output_stream):
    """
    Imprime las recomendaciones de gadgets.
    """
    if recomendaciones:
        output_stream.write(f"\nGadgets Recomendados: {description}\n")
        output_stream.write('-' * 80 + '\n')
        for gadget in recomendaciones:
            output_stream.write(gadget['full_line'] + "\n")
        output_stream.write('-' * 80 + '\n')
    else:
        output_stream.write(f"\nGadgets Recomendados: {description}\n")
        output_stream.write("No se encontraron gadgets que cumplan con el criterio.\n")
        output_stream.write('-' * 80 + '\n')

def filter_xchg_gadgets(gadgets):
    """
    Filtra y retorna gadgets que comienzan con la instrucción 'xchg'.
    """
    return [gadget for gadget in gadgets if gadget['instructions'][0].lower().startswith('xchg')]

def main():
    parser = argparse.ArgumentParser(description='Analizador y Recomendador de Gadgets ROP.')
    parser.add_argument('rop_file', help='Ruta al archivo rop.txt generado por rp++.')
    parser.add_argument('--describe', action='store_true', help='Describir todos los gadgets con detalles.')
    parser.add_argument('--categorize', action='store_true', help='Agrupar gadgets por categorías.')
    parser.add_argument('--recommend-pop', action='store_true', help='Recomendar gadgets que contienen instrucciones POP o PUSH.')
    parser.add_argument('--recommend-ret', action='store_true', help='Recomendar gadgets que terminan con RET.')
    parser.add_argument('--recommend-jmp', action='store_true', help='Recomendar gadgets que contienen JMP.')
    parser.add_argument('--recommend-push', action='store_true', help='Recomendar gadgets que comienzan con PUSH ESP.')
    parser.add_argument('--detect-inc-ret', action='store_true', help='Detectar gadgets que contienen "inc <reg> ; ret".')
    parser.add_argument('--recommend-inc', action='store_true', help='Recomendar gadgets que realizan incrementos o decrementos.')
    parser.add_argument('--filter-xchg', action='store_true', help='Filtrar gadgets que comienzan con la instrucción XCHG.')
    parser.add_argument('--output', type=str, help='Guardar la salida en un archivo de texto.')
    parser.add_argument('--min-instr', type=int, default=2, help='Número mínimo de instrucciones por gadget.')
    parser.add_argument('--max-instr', type=int, default=5, help='Número máximo de instrucciones por gadget.')
    

    args = parser.parse_args()

    gadgets = parse_rop_file(
        args.rop_file, 
        min_instr=args.min_instr, 
        max_instr=args.max_instr
    )

    if args.output:
        try:
            output_file = open(args.output, 'w', encoding='utf-8')
        except IOError as e:
            print(f"Error al abrir el archivo de salida: {e}")
            sys.exit(1)
    else:
        output_file = sys.stdout

    if args.describe:
        output_file.write("Descripción de Gadgets:\n")
        output_file.write('=' * 80 + '\n')
        describe_gadgets(gadgets, output_file)
        output_file.write('\n')

    if args.categorize:
        output_file.write("Gadgets Agrupados por Categorías:\n")
        output_file.write('=' * 80 + '\n')
        categorize_and_print(gadgets, output_file)
        output_file.write('\n')

    if args.recommend_pop:
        recomendaciones = recomendar_gadgets(
            gadgets, 
            criteria=lambda instr: instr.startswith('push ') or instr.startswith('pop ')
        )
        print_recomendaciones(recomendaciones, "Gadgets que contienen instrucciones POP o PUSH.", output_file)

    if args.recommend_ret:
        recomendaciones = [
            gadget for gadget in gadgets 
            if extract_mnemonic(gadget['instructions'][-1]) in ['ret', 'retn']
        ]
        print_recomendaciones(recomendaciones, "Gadgets que terminan con RET.", output_file)

    if args.recommend_jmp:
        recomendaciones = recomendar_gadgets(
            gadgets, 
            criteria=lambda instr: 'jmp ' in instr
        )
        print_recomendaciones(recomendaciones, "Gadgets que contienen instrucciones JMP.", output_file)

    if args.recommend_push:
        recomendaciones = [
            gadget for gadget in gadgets 
            if gadget['instructions'][0].lower().startswith('push esp')
        ]
        print_recomendaciones(recomendaciones, "Gadgets que comienzan con PUSH ESP.", output_file)

    if args.detect_inc_ret:
        recomendaciones = [
            gadget for gadget in gadgets 
            if len(gadget['instructions']) >= 2 and 
               extract_mnemonic(gadget['instructions'][-2]) == 'inc' and
               extract_mnemonic(gadget['instructions'][-1]) == 'ret'
        ]
        print_recomendaciones(recomendaciones, 'Gadgets que contienen "inc <reg> ; ret".', output_file)

    if args.recommend_inc:
        recomendaciones = recomendar_gadgets(
            gadgets, 
            criteria=lambda instr: instr.startswith('inc ') or instr.startswith('dec ')
        )
        print_recomendaciones(recomendaciones, "Gadgets que realizan incrementos o decrementos.", output_file)

    if args.filter_xchg:
        recomendaciones = filter_xchg_gadgets(gadgets)
        print_recomendaciones(recomendaciones, 'Gadgets que comienzan con la instrucción "xchg".', output_file)

    if args.output:
        output_file.close()

    if not any([
        args.describe, args.categorize, args.recommend_pop, 
        args.recommend_ret, args.recommend_jmp, args.recommend_push, 
        args.detect_inc_ret, args.recommend_inc, args.filter_xchg
    ]):
        parser.print_help()

if __name__ == "__main__":
    main()
