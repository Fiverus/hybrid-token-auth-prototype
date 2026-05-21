# Hybrid Token-Based Authentication Prototype

Šis projekts realizē bakalaura darbā aprakstīto praktisko autentifikācijas prototipu.

## Autentifikācijas plūsma

```text
Frontend
  -> API Gateway middleware
  -> Backend application server
  -> Token introspection
  -> OAuth 2.0 authorization check
  -> JWT access token + HttpOnly refresh token
  -> Frontend
```

## Funkcionalitāte

- Lietotāja ievaddati tiek nosūtīti no frontend formas.
- Pieprasījums vispirms iziet API Gateway middleware pārbaudi.
- Backend pārbauda lietotājvārdu un paroli.
- Backend veic ārējā access token introspection pārbaudi.
- Backend pārbauda OAuth 2.0 `client_id` un nepieciešamo `scope`.
- Veiksmīgas pārbaudes gadījumā tiek izsniegts JWT access token.
- Refresh token tiek saglabāts HttpOnly sīkdatnē.
- Aizsargāts resurss pieejams tikai ar derīgu JWT access token.
- Refresh endpoint izsniedz jaunu access token.
- Logout atsauc refresh token.

## Palaišana

```bash
npm install
cp .env.example .env
npm run dev
```

Pēc palaišanas atvērt pārlūkā:

```text
http://localhost:3000
```

## Demo dati

```text
Username: demo
Password: Password123!
External OAuth token: external-valid-token
Client ID: bachelor-client
```

## Curl piemērs

```bash
curl -i -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -H "X-Client-Id: bachelor-client" \
  -d '{"username":"demo","password":"Password123!","externalToken":"external-valid-token"}'
```

## Produkcijas vides piezīmes

Šis ir mācību prototips. Reālā produkcijas vidē būtu jāizmanto īsts OAuth 2.0 / OpenID Connect serveris, datubāze vai Redis refresh token glabāšanai, HTTPS, CSRF aizsardzība un pilnvērtīga auditācija.
