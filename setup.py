from cx_Freeze import setup, Executable


build_exe_options = {
    "includes": ['psycopg2', 'xmltodict'],
    "include_files": ['.env'],
}

setup(
    name="exp_vul_todb",
    version="0.1",
    description="Convert xml_vul to DB",
    options={"build_exe": build_exe_options},
    executables=[Executable('exp_vul_todb.py')],
)
