from opensearchpy import OpenSearch
from opensearch_dsl import Search
import environ
from pathlib import Path


def connect_to_OS(auth, adress):
    return OpenSearch(hosts=[{'host': adress['host'], 'port': adress['port']}],
                        http_compress=True,
                        http_auth=auth,
                        use_ssl=True,
                        verify_certs=False,
                        ssl_assert_hostname=False,
                        ssl_show_warn=False)


def get_search_query(search_query, index_name, client):
    query = {
        "from": 0,
        "query": {
            "bool": {
                "filter": {
                    "range": {
                        "published": {"gte": "now-30d/d"}}},
                "must": [{
                    "query_string": {
                        "query": search_query,
                        "default_operator": "AND",
                        "fields": [
                            "id^4",
                            "title^3",
                            "affectedPackage.packageName^3",
                            "affectedSoftware.name^3",
                            "description",
                            "*"]}}],
                "should": [
                    {"term": {
                        "type": {
                            "value": "unix",
                            "boost": 2}}},
                    {"term": {
                        "type": {
                            "value": "exploit",
                            "boost": 2.5}
                        }},
                    {"term": {
                        "type": {
                            "value": "software",
                            "boost": 2}}},
                    {"term": {
                        "type": {
                            "value": "nvd",
                            "boost": 2}}},
                    {"term": {
                        "type": {
                            "value": "info",
                            "boost": 0.3}}}
                    ]
            }
        },
        "size": 20,
        "sort": [
            {
                "_score": {
                    "order": "desc"}
            },
            {
                "published": {
                    "order": "desc"}
            }
        ]
        }
    s = Search(index=index_name)
    s.update_from_dict(query)
    s = s.using(client)
    return s.execute()


if __name__ == "__main__":
    env = environ.Env()
    environ.Env.read_env(env_file=Path('./cve_docker/.env'))
    adress = eval(env('ES_ADDRESS'))
    auth = tuple((env('ES_AUTH')).split())

    # adress = eval(adress)
    print(adress)
    print(auth)

    index_name = 'es6_bulletins_bulletin'
    search_query = 'linux OR firefox'

    client = connect_to_OS(auth, adress)

    response = get_search_query(search_query, index_name, client)

    for hit in response:
        #print(hit.meta.score, hit.meta.sort, hit.title)
        print(hit.title, hit.description)

    print('########################')
    print(response.success())
    # True
    print(response.took)
    # 12
    print(response.hits.total.relation)
    # eq
    print(response.hits.total.value)
    # 142
    print(response.hits.total)

    print(response.hits[2].origin)

    # # for tag in response.aggregations.per_tag.buckets:
    # #     print(tag.key, tag.max_lines.value)
