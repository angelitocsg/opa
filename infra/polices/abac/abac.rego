package abac.authz

import rego.v1

import data.items

default allow := false

allow if {
	some item in items
	action_allowed(item, input.appid, input.apikey, input.canal)
	action_allowed_apikey(item.apikey)
	action_allowed_rota(input.rota, item.rotas)
	action_allowed_documento(input.documento, item.documentos)
}

action_allowed(item, appid, apikey, canal) if {
	appid == item.appid
	apikey == item.apikey
	canal == item.canal
}

action_allowed_apikey(apikey) if {
	apikey == token.apikey
}

action_allowed_rota(rota, rotas) if {
	rota in rotas
}

action_allowed_documento(documento, documentos) if {
	documento in documentos
}

token := {"apikey": apikey} if {
	[_, encoded] := split(input.token.authorization, " ")
	[_, payload, _] := io.jwt.decode(encoded)
	apikey := payload[input.token.field]
}
