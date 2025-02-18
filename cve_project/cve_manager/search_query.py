from opensearchpy import OpenSearch
from opensearch_dsl import Search
import environ
from pathlib import Path


def connect_to_OS():
    env = environ.Env()
    environ.Env.read_env(env_file=Path('./cve_docker/.env'))
    # adress = eval(env('ES_ADDRESS'))
    auth = tuple((env('ES_AUTH')).split())
    adress_host = env('ES_ADDRESS_HOST')
    adress_port = env('ES_ADDRESS_PORT')

    return OpenSearch(hosts=[{'host': adress_host, 'port': adress_port}],
                        http_compress=True,
                        http_auth=auth,
                        use_ssl=True,
                        verify_certs=False,
                        ssl_assert_hostname=False,
                        ssl_show_warn=False)


def get_search_query(search_query, query_date, query_count):
    index_name = 'os_bulletins'
    query = {
        "from": 0,
        "query": {
            "bool": {
                "filter": {
                    "range": {
                        "published": {"gte": f"now-{query_date}M/M"}}},
                "must": [{
                    "query_string": {
                        "query": search_query,
                        "default_operator": "AND",
                        "fields": [
                            "id^4",
                            "title^3",
                            "affectedPackage.packageName^4",
                            "affectedSoftware.name^4",
                            "affectedSoftware.soft.name^4",
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
                            "value": "fstekdbu",
                            "boost": 4}}},
                    {"term": {
                        "type": {
                            "value": "info",
                            "boost": 0.3}}}
                    ]
            }
        },
        "size": query_count,
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

    client = connect_to_OS()

    s = Search(index=index_name)
    s.update_from_dict(query)
    s = s.using(client)

    return s.execute()


def get_pack_query(packageName, os_name):
    index_name = 'os_bulletins'
    query = {
        "query":{
            "bool":{
            "must": [
                {"match": {
                "bulletinFamily": "unix"
                }},
                {"match": {
                "affectedPackage.OS": os_name
                }},
                {"term": {
                    "affectedPackage.packageName.keyword": packageName
                }}
            ]
            }
        },
        "size": 200,
        "sort": [
                {
                "cvss.score": {
                    "order": "desc"}
                },
                {
                "published": {
                    "order": "desc"}
                }
                ]
        }

    client = connect_to_OS()
    s = Search(index=index_name)
    s.update_from_dict(query)
    s = s.using(client)
    return s.execute()


def get_detail_query(hit_id):
    index_name = 'os_bulletins'
    query = {
        "query":{
            "match":{
                "_id":hit_id
            }
        }
    }

    client = connect_to_OS()
    s = Search(index=index_name)
    s.update_from_dict(query)
    s = s.using(client)
    return s.execute()


def get_bdu_detail_query():
    index_name = 'os_bulletins'
    query = {
        "aggs": {
            "by_type": {
                "terms": {
                "field": "type.keyword"
                },
            "aggs": {
            "group_docs": {
                "top_hits": {
                "size": 1,
                "sort": [{
                    "@timestamp": {
                        "order": "desc"
                    }
                }],
                "_source": {
                    "includes": [ "@timestamp" ]
                }
                }
            }
            }
        }
    },
    "size": 0
  }

    client = connect_to_OS()
    s = Search(index=index_name)
    s.update_from_dict(query)
    s = s.using(client)
    return s.execute()


def get_bdu_linux_query():
    index_name = 'os_bulletins'
    query = {
        "query": {
    "match":{
      "bulletinFamily": "unix"
    }
  },
  "aggs": {
    "by_type": {
        "terms": {
          "field": "type.keyword"
        },
        "aggs": {
          "group_docs": {
            "top_hits": {
              "size": 1,
              "sort": [{
                  "@timestamp": {
                    "order": "desc"
                  }
              }],
              "_source": {
                "includes": [ "@timestamp" ]
            }

            }
          }
        }
    }
  },
    "size": 0
  }

    client = connect_to_OS()
    s = Search(index=index_name)
    s.update_from_dict(query)
    s = s.using(client)
    return s.execute()

if __name__ == "__main__":
    d = {}
    response = get_bdu_linux_query()

    for hit in response.aggregations.by_type.buckets:
        print(hit.key, hit.doc_count)
        print(hit.group_docs.hits.hits[0]._source['@timestamp'])
        d.update({hit.key: [hit.doc_count, hit.group_docs.hits.hits[0]._source['@timestamp']]})
    print(d)

    print('########################')
    print(response.success())
    # True
    print(response)
    # 12
    print(response.hits.total.relation)
    # eq
    print(response.hits.total.value)
    # 142
    print(response.hits.total)

    # # for tag in response.aggregations.per_tag.buckets:
    # #     print(tag.key, tag.max_lines.value)
