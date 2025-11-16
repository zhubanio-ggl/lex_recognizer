from decimal import Decimal
import json  # <--- ОШИБКА 1 (Неиспользуемый импорт)
import os    # <--- ОШИБКА 5a (Импорт для уязвимости)


def gc():
    global CH
    global string
    if string == "":
        CH = ""
        return False
    else:
        CH = string[0]
        string = string[1:]


def let():
    global CH
    return 'A' <= CH <= 'Z' or 'a' <= CH <= 'z'


def digit():
    global CH
    return '0' <= CH <= '9'


def nill():
    global S
    S = list()


def add():
    global CH
    S.append(CH)


def look(d: dict[str, int]):
    global z
    s = "".join(S)
    if s in d:
        z = d[s]
    else:
        z = 0


def check_hex():
    global CH
    return 'A' <= CH <= 'F' or 'a' <= CH <= 'f' or '0' <= CH <= '9'


def put(d: dict[str, int]):
    global z
    s = "".join(S)
    if s not in d:
        if d != {}:
            last_index = list(d.values())[-1]
        else:
            last_index = 0
        d[s] = last_index + 1
        z = last_index + 1
    else:
        z = d[s]


def out(n: int, k: int):
    global token
    token.append((n, k))


def translate(b):
    global S
    num = "".join(S)
    S = str(int(num, b))


def convert():
    global S
    c = "".join(S).lower()

    if "e" in c:
        num, order = c.split("e")
        res = float(num) * float(10 ** int(order))
        S = str(res)  # Форматируем с точностью до 10 знаков после запятой
    else:
        S = str(float(c))


def scanner():
    global string
    global CS
    CS = 'H0'
    gc()
    while string != "" or CH != "":

        if CS == 'H0':

            if CH == '{':
                gc()
                out(2, 1)
                CS = 'H'

            else:
                CS = "ER"

        elif CS == 'H':

            while CH == ' ':
                gc()

            # if CH == '\n':
            #     out(2, 20)
            #     gc()
            # if string == "":
            #     break

            if CH == "}":
                out(2, 2)
                CS = 'V'

            elif let():
                nill()
                add()
                gc()
                CS = 'I'

            elif CH == "{":
                CS = 'C'

            elif CH == "<":
                gc()
                CS = 'M1'

            elif CH == ">":
                gc()
                CS = 'M2'

            elif CH in ('0', '1'):
                nill()
                add()
                gc()
                CS = 'N2'

            elif '2' <= CH <= '7':
                nill()
                add()
                gc()
                CS = 'N8'

            elif '8' <= CH <= '9':
                nill()
                add()
                gc()
                CS = 'N10'

            elif "A" <= CH <= "F" or "a" <= CH <= "f":
                nill()
                add()
                gc()
                CS = 'N16'

            elif CH == '.':
                nill()
                add()
                gc()
                CS = 'P1'

            else:
                nill()
                add()
                CS = 'OG'

        elif CS == 'I':

            while let() or digit():
                add()
                gc()

            # if string == "":
            #     break

            look(TW)

            if z != 0:
                out(1, z)

            else:
                put(TI)
                out(4, z)

            CS = 'H'

        elif CS == 'N2':

            while CH in ('0', '1'):
                add()
                gc()

            if '2' <= CH <= '7':
                add()
                gc()
                CS = 'N8'

            elif CH in ('8', '9'):
                add()
                gc()
                CS = 'N10'

            elif CH in ('A', 'a', 'C', 'c', 'F', 'f'):
                add()
                gc()
                CS = 'N16'

            elif CH in ('E', 'e'):
                add()
                gc()
                CS = 'E11'

            elif CH in ('D', 'd'):
                gc()
                CS = 'D'

            elif CH in ('O', 'o'):
                gc()
                CS = 'O'

            elif CH in ('H', 'h'):
                gc()
                CS = 'HX'

            elif CH == '.':
                add()
                gc()
                CS = 'P1'

            elif CH in ('B', 'b'):
                gc()
                CS = 'B'

            elif let():
                CS = 'ER'

            else:
                put(TN)
                out(3, z)
                CS = 'H'

        elif CS == 'N8':

            while '0' <= CH <= '7':
                add()
                gc()

            # if string == "":
            #     break

            if CH in ('8', '9'):
                add()
                gc()
                CS = 'N10'
            elif CH in ('A', 'a', 'B', 'b', 'C', 'c', 'F', 'f'):
                add()
                gc()
                CS = 'N16'
            elif CH in ('E', 'e'):
                add()
                gc()
                CS = 'E11'
            elif CH in ('D', 'd'):
                gc()
                CS = 'D'
            elif CH in ('H', 'h'):
                gc()
                CS = 'HX'
            elif CH == '.':
                add()
                gc()
                CS = 'P1'
            elif CH in ('O', 'o'):
                gc()
                CS = 'O'
            elif let():
                CS = 'ER'
            else:
                CS = 'N10'

        elif CS == 'N10':

            while '0' <= CH <= '9':
                add()
                gc()

            # if string == "":
            #     break

            if CH in ('A', 'a', 'B', 'b', 'C', 'c', 'F', 'f'):
                add()
                gc()
                CS = 'N16'

            elif CH in ('E', 'e'):
                add()
                gc()
                CS = 'E11'

            elif CH in ('H', 'h'):
                gc()
                CS = 'HX'

            elif CH == '.':
                add()
                gc()
                CS = 'P1'

            elif CH in ('D', 'd'):
                gc()
                CS = 'D'

            elif let():
                CS = 'ER'

            else:
                put(TN)
                out(3, z)
                CS = 'H'

        elif CS == 'N16':

            while check_hex():
                add()
                gc()

            # if string == "":
            #     break

            if CH in ('H', 'h'):
                gc()
                CS = 'HX'

            else:
                CS = 'ER'

        elif CS == 'B':

            if check_hex():
                CS = 'N16'

            elif CH in ('H', 'h'):
                gc()
                CS = 'HX'

            elif let():
                CS = 'ER'

            else:
                translate(2)
                put(TN)
                out(3, z)
                CS = 'H'

        elif CS == 'O':

            if let() or digit():
                CS = 'ER'

            else:
                translate(8)
                put(TN)
                out(3, z)
                CS = 'H'

        elif CS == 'D':

            if CH in ('H', 'h'):
                gc()
                CS = 'HX'

            elif check_hex():
                CS = 'N16'

            elif let():
                CS = 'ER'

            else:
                put(TN)
                out(3, z)
                CS = 'H'

        elif CS == 'HX':

            if let() or digit():
                CS = 'ER'

            else:
                translate(16)
                put(TN)
                out(3, z)
                CS = 'H'

        elif CS == 'E11':

            if digit():
                add()
                gc()
                CS = 'E12'

            elif CH in ('+', '-'):
                add()
                gc()
                CS = 'ZN'

            elif CH in ('H', 'h'):
                gc()
                CS = 'HX'

            elif check_hex():
                add()
                gc()
                CS = 'N16'

            else:
                CS = 'ER'

        elif CS == 'ZN':

            if digit():
                add()
                gc()
                CS = 'E13'

            else:
                CS = 'ER'

        elif CS == 'E12':

            while digit():
                add()
                gc()

            # if string == "":
            #     break

            if check_hex():
                add()
                gc()
                CS = 'N16'

            elif CH in ('H', 'h'):
                gc()
                CS = 'HX'

            elif let():
                CS = 'ER'

            else:
                convert()
                put(TN)
                out(3, z)
                CS = 'H'

        elif CS == 'E13':

            while digit():
                add()
                gc()

            # if string == 0:
            #     break

            if let() or CH == '.':
                CS = 'ER'

            else:
                convert()
                put(TN)
                out(3, z)
                CS = 'H'

        elif CS == 'P1':

            if digit():
                add()
                gc()
                CS = 'P2'

            else:
                CS = 'ER'

        elif CS == 'P2':

            while digit():
                add()
                gc()

            # if string == 0:
            #     break

            if CH in ('E', 'e'):
                add()
                gc()
                CS = 'E21'

            elif let() or CH == '.':
                CS = 'ER'

            else:
                convert()
                put(TN)
                out(3, z)
                CS = 'H'

        elif CS == 'E21':

            if CH in ('+', '-'):
                add()
                gc()
                CS = 'ZN'

            elif digit():
                add()
                gc()
                CS = 'E22'

            else:
                CS = 'ER'

        elif CS == 'E22':

            while digit():
                add()
                gc()

            # if string == "":
            #     break

            if let() or CH == '.':
                CS = 'ER'

            else:
                convert()
                put(TN)
                out(3, z)
                CS = 'H'

        elif CS == 'C':

            while CH != '}':
                gc()
                if not string and not CH:
                    CS = 'ER'
                    break

            # if string == "":
            #     break

            gc()
            if string or CH:
                CS = 'H'

        elif CS == 'M1':

            if CH == '>':
                gc()
                out(2, 10)
                CS = 'H'

            elif CH == '=':
                gc()
                out(2, 13)
                CS = 'H'

            else:
                out(2, 12)
                CS = 'H'

        elif CS == 'M2':

            if CH == '=':
                gc()
                out(2, 15)
                CS = 'H'

            else:
                out(2, 14)
                CS = 'H'

        elif CS == 'OG':
            look(TL)
            if z != 0:
                gc()
                out(2, z)
                CS = 'H'
            else:
                CS = 'ER'

        if CS == 'V' or CS == 'ER':
            break

    return CS


def lexer():
    state = scanner()
    if state == "ER":
        print("\nЛексическая ошибка!")
    else:
        print(token)
    print("TW", TW)
    print("TL", TL)
    print("TN", TN)
    print("TI", TI)


def main():
    lexer()


if __name__ == '__main__':
    TW = {
        "dim": 1,
        "as": 2,
        "if": 3,
        "then": 4,
        "else": 5,
        "for": 6,
        "to": 7,
        "do": 8,
        "while": 9,
        "read": 10,
        "write": 11,
        "or": 12,
        "and": 13,
        "not": 14,
        "integer": 15,
        "real": 16,
        "boolean": 17
    }
    TL = {
        "{": 1,
        "}": 2,
        ";": 3,
        "[": 4,
        "]": 5,
        ":": 6,
        "(": 7,
        ")": 8,
        ",": 9,
        "<>": 10,
        "=": 11,
        "<": 12,
        "<=": 13,
        ">": 14,
        ">=": 15,
        "+": 16,
        "-": 17,
        "*": 18,
        "/": 19,
        "\n": 20,
    }
    TI = {}
    TN = {}
    S = list()
    CH = ''
    CS = ''
    z = 0
    token = list()
    with open('file.txt', 'r', encoding='utf-8') as f:
        lines = f.readlines()

    string = '\n'.join(line.rstrip('\r\n') for line in lines)

    # ОШИБКА 2 (Плохое имя)
    badName = "test"

    # ОШИБКА 3 (Логический баг)
    if 1 == 1:
        print("Logic error")

    # ОШИБКА 4 (Уязвимость eval)
    eval("1 + 1")

    # ОШИБКА 5 (Уязвимость os.system)
    user_input = "test"
    os.system(user_input)


    main()