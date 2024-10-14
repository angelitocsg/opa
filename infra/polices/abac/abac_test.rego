package abac.authz

# Teste de política ABAC

test_allow_access {
    # Teste de caso válido, onde todos os atributos coincidem
    input := {
        "appid": "myapp1",
        "apikey": "a9971a3b-4b20-4acd-a8d7-7ed43bd90942",
        "documento": "51362886000154",
        "canal": "CO",
        "rota": "/simulacoes",
        "token": {
            "authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c3IiOiJhbmdlbGl0byIsImhlbGxvIjoid29ybGQiLCJzdWIiOiJhOTk3MWEzYi00YjIwLTRhY2QtYThkNy03ZWQ0M2JkOTA5NDIiLCJuYmYiOjE3Mjg4NzM0NDQsImV4cCI6MTcyODg5MTQ0NCwiaWF0IjoxNzI4ODczNDQ0fQ.wTHDPgetRks61A27Fe0I_C7RpPzWcGY3j7TRwaG8jS0",
            "field": "sub"
        }
    }
    
    allow with input as input
}

test_deny_access_wrong_appid {
    # Teste de caso onde a appid está errada
    input := {
        "appid": "wrong-appid",
        "apikey": "a9971a3b-4b20-4acd-a8d7-7ed43bd90942",
        "documento": "51362886000154",
        "canal": "CO",
        "rota": "/simulacoes"
    }
    
    not allow with input as input
}

test_deny_access_wrong_apikey {
    # Teste de caso onde a apikey está errada
    input := {
        "appid": "myapp1",
        "apikey": "wrong-apikey",
        "documento": "51362886000154",
        "canal": "CO",
        "rota": "/simulacoes"
    }
    
    not allow with input as input
}

test_deny_access_wrong_document {
    # Teste de caso onde o documento está incorreto
    input := {
        "appid": "myapp1",
        "apikey": "a9971a3b-4b20-4acd-a8d7-7ed43bd90942",
        "documento": "wrong-documento",
        "canal": "CO",
        "rota": "/simulacoes"
    }
    
    not allow with input as input
}

test_deny_access_wrong_rota {
    # Teste de caso onde a rota está incorreta
    input := {
        "appid": "myapp1",
        "apikey": "a9971a3b-4b20-4acd-a8d7-7ed43bd90942",
        "documento": "51362886000154",
        "canal": "CO",
        "rota": "/wrong-rota"
    }
    
    not allow with input as input
}

test_deny_access_wrong_canal {
    # Teste de caso onde o canal está incorreto
    input := {
        "appid": "myapp1",
        "apikey": "a9971a3b-4b20-4acd-a8d7-7ed43bd90942",
        "documento": "51362886000154",
        "canal": "wrong-canal",
        "rota": "/simulacoes"
    }
    
    not allow with input as input
}
