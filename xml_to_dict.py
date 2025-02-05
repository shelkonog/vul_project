import xmltodict
import json
import sys
from dateutil import parser


def formateDate(str_data):
    return str(parser.parse(str_data).date()) + 'T00:00:05.600000009Z'

def createJSON(xmlFile):

    try:
        with open(xmlFile, 'r', encoding='utf-8') as file:
            my_xml = file.read()
    except OSError as e:
        print(f"Произошла ошибка при загрузке файла xml с УЯ: {e}")
        sys.exit(1)
    except FileNotFoundError as e:
        print(f"Произошла ошибка при загрузке файла xml с УЯ: {e}")
        sys.exit(1)

    # Получили словарь из БД ФСТЭК
    my_dict = xmltodict.parse(my_xml)

    # Формируем поле даты в формате ISO8601

    for key2 in my_dict["vulnerabilities"]["vul"]:
        for key3, value3 in key2.items():
            if key3 == "identify_date":
                if value3 == "Данные уточняются":
                    value3 = "01.01.2000"
                key2["identify_date"] = formateDate(value3)

    # Создаем файл формата json с УЯ Logstash + OpenSearch
    try:
        with open('fstek_bdu.json', 'w') as fjson:
            for vul_doc in my_dict["vulnerabilities"]["vul"]:
                json.dump(vul_doc, fjson, ensure_ascii=False)
                fjson.write('\n')
    except OSError as e:
        print(f"Произошла ошибка при сохранении файла json с УЯ: {e}")
        sys.exit(1)
    except FileNotFoundError as e:
        print(f"Произошла ошибка при сохранении файла json с УЯ: {e}")
        sys.exit(1)


xmlFile = 'export_2.xml'
createJSON(xmlFile)
