import xmltodict
import psycopg2
from psycopg2 import Error
import copy
import os
import json


xmlFile = 'export_2.xml'


def parseXML(xmlFile):
    with open(xmlFile, 'r', encoding='utf-8') as file:
        my_xml = file.read()

    cve_dict = dict()
    cve_soft_dict = dict()
    cve_soft_list = []
    cve_list = []

    my_dict = xmltodict.parse(my_xml)

    for cve in my_dict['vulnerabilities']['vul']:
        for cve_head, cve_param in cve.items():
            if cve_head == 'identifier':
                cve_dict[cve_head] = cve_param
                cve_soft_dict[cve_head] = cve_param

            if cve_head == 'vulnerable_software':
                if type(cve_param['soft']) is list:
                    for soft_cve_param in cve_param['soft']:
                        for soft_head, soft_param in soft_cve_param.items():
                            if soft_head == 'types':
                                if soft_param is not None:
                                    cve_soft_dict['soft_type'] = soft_param['type']
                                else:
                                    cve_soft_dict['soft_type'] = soft_param
                            elif soft_head == 'registry_number':
                                pass
                            else:
                                cve_soft_dict['soft_' + soft_head] = soft_param

                        cve_soft_list.append(copy.deepcopy(cve_soft_dict))
                else:
                    soft_cve_param = cve_param['soft']
                    for soft_head, soft_param in soft_cve_param.items():
                        if soft_head == 'types':
                            if soft_param is not None:
                                cve_soft_dict['soft_type'] = soft_param['type']
                            else:
                                cve_soft_dict['soft_type'] = soft_param
                        elif soft_head == 'registry_number':
                            pass
                        else:
                            cve_soft_dict['soft_' + soft_head] = soft_param

                    cve_soft_list.append(copy.deepcopy(cve_soft_dict))

            elif cve_head == 'environment':
                pass

            elif cve_head == 'cwe':
                cve_dict['cwe_identifier'] = cve_param['identifier']

            elif cve_head == 'cvss':
                for cvss_head, cvss_param in cve_param['vector'].items():
                    cve_dict['cvss_' + cvss_head[1:]] = cvss_param

            elif cve_head == 'cvss3':
                for cvss_head, cvss_param in cve_param['vector'].items():
                    cve_dict['cvss3_' + cvss_head[1:]] = cvss_param

            elif cve_head == 'identifiers':
                if type(cve_param['identifier']) is list:
                    cve_dict['identifiers'] = cve_param['identifier'][0]
                else:
                    cve_dict['identifiers'] = cve_param['identifier']
            else:
                cve_dict[cve_head] = cve_param
        cve_list.append(copy.deepcopy(cve_dict))

    return cve_list, cve_soft_list


def conn_to_db():
    try:
        # Подключение к существующей базе данных
        connection = psycopg2.connect(
                        user=os.environ.get('PG_USER'),
                        password=os.environ.get('PG_PASSWORD'),
                        host=os.environ.get('PG_HOST'),
                        port=os.environ.get('PG_PORT'),
                        database=os.environ.get('PG_DATABASE'))

        # Курсор для выполнения операций с базой данных
        cursor = connection.cursor()
        print("Подключение к БД выполнено...")

    except (Exception, Error) as error:
        print("Ошибка при подключении к БД", error)

    return cursor, connection


def req_drop_tbl(name_tbl):
    return f"""DROP TABLE {name_tbl};"""


def exists_tbl(cursor, name_tbl):
    tblExists = f"""SELECT table_name
                    FROM information_schema.tables
                    WHERE table_schema='public'
                    AND table_name='{name_tbl}';"""
    cursor.execute(tblExists)
    return bool(cursor.rowcount)


def load_to_db(name_tbl, name_dct):
    cols = name_dct.keys()
    cols_str = ', '.join(cols)
    vals = [json.dumps(name_dct[k]) if type(name_dct[k]) is dict else name_dct[k] for k in cols]
    vals_str = ', '.join(["%s" for i in range(len(vals))])
    ins_cve_soft = f"""INSERT INTO {name_tbl} ({cols_str}) VALUES ({vals_str})"""
    return ins_cve_soft, vals


def req_update_tbl(name_cve_tbl, name_tbl_rez):
    col_cve_tbl = '''identifier, name, description, cwe_identifier,
                     identify_date, "cvss_score", "cvss_text",
                     "cvss3_score", "cvss3_text", severity, solution,
                     vul_status, exploit_status, fix_status, sources,
                     identifiers, other, vul_incident, vul_class'''

    col_soft_tbl = '''identifier, soft_vendor, soft_name,
                      soft_version, soft_platform, soft_type'''

    if name_tbl_rez == 'cve_tbl_rez':
        col_tbl = col_cve_tbl
    else:
        col_tbl = col_soft_tbl

    update_cve_tbl = f"""insert into {name_tbl_rez} ({col_tbl})
                        select {col_tbl}
                        from {name_cve_tbl} as T2
                        where
                        not exists (
                            select identifier
                            from {name_tbl_rez} as T1
                            where
                                T1.identifier = T2.identifier);"""

    return update_cve_tbl


def add_cve_tobls():

    name_tbl_cve = 'cve_tbl'
    name_tbl_soft = 'cve_soft_tbl'
    tbl_cve = 'cve_tbl_rez'
    tbl_soft = 'soft_tbl_rez'

    print('Обработка данных перед загрузкой в БД...')
    cve_list, cve_soft_list = parseXML(xmlFile)

    cursor, connector = conn_to_db()

    try:
        if exists_tbl(cursor, name_tbl_cve):
            cursor.execute(req_drop_tbl(name_tbl_cve))
            cursor.execute(req_creare_cve(name_tbl_cve))
        else:
            cursor.execute(req_creare_cve(name_tbl_cve))

        if exists_tbl(cursor, name_tbl_soft):
            cursor.execute(req_drop_tbl(name_tbl_soft))
            cursor.execute(req_creare_soft(name_tbl_soft))
        else:
            cursor.execute(req_creare_soft(name_tbl_soft))

        print('Загрузка данных в БД началась...')
        for dct in cve_list:
            ins_cve, vals = load_to_db(name_tbl_cve, dct)
            cursor.execute(ins_cve, vals)

        for dct in cve_soft_list:
            ins_cve_soft, vals = load_to_db(name_tbl_soft, dct)
            cursor.execute(ins_cve_soft, vals)
        print('Данные загруженны в БД...')

        print('Синхронизация данных таблиц началась...')
        if exists_tbl(cursor, tbl_cve):
            cursor.execute(req_update_tbl(name_tbl_cve, tbl_cve))
            print(f'В БД добавлено новых описаний УЯ: {cursor.rowcount}')
        else:
            print('Базовая таблица не создана, необходимо запустить мастер создания таблиц...')
        if exists_tbl(cursor, tbl_soft):
            cursor.execute(req_update_tbl(name_tbl_soft, tbl_soft))
        else:
            print('Базовая таблица не создана, необходимо запустить мастер создания таблиц...')
        print('Синхронизация данных завершена...')

    except (Exception, Error) as error:
        print("Ошибка при работе с БД ", error)

    connector.commit()

    if connector:
        cursor.close()
        connector.close()
        print("Подключение к БД закрыто")


def req_creare_soft(name_tbl):
    req_create_soft = f"""CREATE TABLE {name_tbl}
                        (id BIGSERIAL PRIMARY KEY NOT NULL,
                        identifier varchar,
                        soft_vendor varchar,
                        soft_name varchar,
                        soft_version varchar,
                        soft_platform varchar,
                        soft_type varchar);"""
    return req_create_soft


def req_creare_cve(name_tbl):
    req_create_cve = f"""CREATE TABLE {name_tbl}
                        (id BIGSERIAL PRIMARY KEY NOT NULL,
                        identifier varchar NOT NULL,
                        name varchar NOT NULL,
                        description varchar,
                        cwe_identifier varchar,
                        identify_date date,
                        "cvss_score" varchar,
                        "cvss_text" varchar,
                        "cvss3_score" varchar,
                        "cvss3_text" varchar,
                        severity varchar,
                        solution varchar,
                        vul_status varchar,
                        exploit_status varchar,
                        fix_status varchar,
                        sources varchar,
                        identifiers varchar,
                        other varchar,
                        vul_incident varchar,
                        vul_class varchar);"""
    return req_create_cve


def create_fth_tbls():
    name_tbl_cve = 'cve_tbl_rez'
    name_tbl_soft = 'soft_tbl_rez'

    cursor, connector = conn_to_db()

    # Создание таблицы 'soft_tbl_rez'
    if exists_tbl(cursor, name_tbl_soft):
        print(f'Таблица {name_tbl_soft} уже существует в БД')
    else:
        cursor.execute(req_creare_soft(name_tbl_soft))
        print(f"Таблица {name_tbl_soft} успешно создана...")

    # Создание таблицы 'cve_tbl_rez'
    if exists_tbl(cursor, name_tbl_cve):
        print(f'Таблица {name_tbl_cve} уже существуют в БД')
    else:
        cursor.execute(req_creare_cve(name_tbl_cve))
        print(f"Таблица {name_tbl_cve} успешно создана...")

    connector.commit()

    if connector:
        cursor.close()
        connector.close()
        print("Подключение к БД закрыто.")


create_fth_tbls()
add_cve_tobls()
