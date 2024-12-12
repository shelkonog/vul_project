from datetime import datetime
from psycopg2 import Error
import xmltodict
import psycopg2
import copy
import os
import json


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
                cve_soft_dict['identifier_id'] = cve_param

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

            elif cve_head == 'identify_date':
                try:
                    datetime.strptime(cve_param, "%d.%m.%Y")
                    cve_dict[cve_head] = cve_param
                except ValueError:
                    cve_dict[cve_head] = None

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


def insert_cve_tbl(cursor, name_tbl, name_list):
    for dct in name_list:
        cols = dct.keys()
        cols_str = ', '.join(cols)
        vals = [json.dumps(dct[k]) if type(dct[k]) is dict else dct[k] for k in cols]
        vals_str = ', '.join(["%s" for i in range(len(vals))])
        ins_cve = f"""INSERT INTO {name_tbl} ({cols_str}) VALUES ({vals_str})"""
        cursor.execute(ins_cve, vals)


def insert_other_tbl(cursor, name_tbl, key, soft_tbl, filter=''):

    req_type_soft = f"""INSERT INTO {name_tbl} ({key})
                        select {key} from
                        (SELECT DISTINCT {key} FROM {soft_tbl}) tbl
                        {filter};"""

    cursor.execute(req_type_soft)


def req_update_tbl(cursor, name_tbl, name_tbl_rez, col, key, filter):

    req_update_tbl = f"""insert into {name_tbl_rez} ({col})
                            select {col}
                            from {name_tbl} as T2
                            where
                            not exists (
                                select {key}
                                from {name_tbl_rez} as T1
                                {filter});"""

    if exists_tbl(cursor, name_tbl_rez):
        cursor.execute(req_update_tbl)
        print(f'  В БД добавлено новых записей: {cursor.rowcount}')
    else:
        print(f'Базовая таблица не создана, необходимо создать модель таблицы {name_tbl_rez}')


def creare_tbl(cursor, name_tbl, col_tbl):
    req_create_tbl = f"""CREATE TABLE {name_tbl}
                        ({col_tbl});"""

    if exists_tbl(cursor, name_tbl):
        cursor.execute(req_drop_tbl(name_tbl))
        cursor.execute(req_create_tbl)
    else:
        cursor.execute(req_create_tbl)


def proc_cve_db():

    # Файл с БД УЯ
    xmlFile = 'export_2.xml'

    # Описание таблицы с CVE
    name_tbl_cve = 'cve_tbl'
    tbl_cve = 'cve_tbl_rez'
    col_tbl_cve = '''id BIGSERIAL PRIMARY KEY NOT NULL,
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
                        vul_class varchar'''
    col_cve = '''identifier, name, description, cwe_identifier,
                     identify_date, "cvss_score", "cvss_text",
                     "cvss3_score", "cvss3_text", severity, solution,
                     vul_status, exploit_status, fix_status, sources,
                     identifiers, other, vul_incident, vul_class'''
    key_col_cve = 'identifier'
    fltr_upd_cve = 'where T1.identifier = T2.identifier'

    # Описание таблицы с ПО
    name_tbl_soft = 'cve_soft_tbl'
    tbl_soft = 'soft_tbl_rez'
    col_tbl_soft = '''id BIGSERIAL PRIMARY KEY NOT NULL,
                        identifier_id varchar,
                        soft_vendor varchar,
                        soft_name varchar,
                        soft_version varchar,
                        soft_platform varchar,
                        soft_type varchar'''
    col_soft = '''identifier_id, soft_vendor, soft_name,
                      soft_version, soft_platform, soft_type'''
    key_col_soft = 'identifier_id'
    fltr_upd_soft = 'where T1.identifier_id = T2.identifier_id'

    # Описание таблицы с типами ПО
    name_tbl_type = 'tbl_soft_type'
    tbl_type = 'tbl_soft_type_rez'
    col_tbl_type = '''id BIGSERIAL PRIMARY KEY NOT NULL,
                        soft_type varchar NOT NULL'''
    col_soft_type = 'soft_type'
    fltr_ins_type = f"where tbl.{col_soft_type} not like '{{%}}'"
    fltr_upd_type = 'where T1.soft_type = T2.soft_type'

    # Описание таблицы с наименованием ПО
    tbl_name = 'tbl_soft_name'
    tbl_name_rez = 'tbl_soft_name_rez'
    col_tbl_name = '''id BIGSERIAL PRIMARY KEY NOT NULL,
                        soft_name varchar NOT NULL,
                        soft_version varchar'''
    col_name = 'soft_name, soft_version'
    fltr_upd_name = 'where T1.soft_name = T2.soft_name and T1.soft_version = T2.soft_version'

    print()
    print('Обработка данных перед загрузкой в БД...')
    cve_list, cve_soft_list = parseXML(xmlFile)
    print('  Данные подготовлены')

    cursor, connector = conn_to_db()

    try:
        creare_tbl(cursor, name_tbl_cve, col_tbl_cve)
        creare_tbl(cursor, name_tbl_soft, col_tbl_soft)

        creare_tbl(cursor, name_tbl_type, col_tbl_type)
        creare_tbl(cursor, tbl_name, col_tbl_name)
        print('БД подготовлено для загрузки данных')

        print('Загрузка данных в БД началась...')
        insert_cve_tbl(cursor, name_tbl_cve, cve_list)
        print('  Загружен перечень уязвимостей')
        insert_cve_tbl(cursor, name_tbl_soft, cve_soft_list)
        print('  Загружен перечень ПО')
        insert_other_tbl(cursor, name_tbl_type, col_soft_type, name_tbl_soft, fltr_ins_type)
        print('  Загружено описание типов ПО')
        insert_other_tbl(cursor, tbl_name, col_name, name_tbl_soft)
        print('  Загружено описание наименований ПО')
        print('Все данные загруженны в БД')

        print('Синхронизация таблицы с УЯ началась...')
        req_update_tbl(cursor, name_tbl_cve, tbl_cve, col_cve, key_col_cve, fltr_upd_cve)
        print('Синхронизация таблицы с ПО началась...')
        req_update_tbl(cursor, name_tbl_soft, tbl_soft, col_soft, key_col_soft, fltr_upd_soft)
        print('Синхронизация таблицы с типом ПО началась...')
        req_update_tbl(cursor, name_tbl_type, tbl_type, col_soft_type, col_soft_type, fltr_upd_type)
        print('Синхронизация таблицы с наименованием ПО началась...')
        req_update_tbl(cursor, tbl_name, tbl_name_rez, col_name, col_name, fltr_upd_name)
        print('Синхронизация данных завершена')

    except (Exception, Error) as error:
        print("Ошибка при работе с БД ", error)

    connector.commit()

    if connector:
        cursor.close()
        connector.close()
        print("Подключение к БД закрыто")


if __name__ == "__main__":
    proc_cve_db()
