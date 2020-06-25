# Dokumentace k 1. úloze do IPK 2019/2020  
Jméno a příjmení: Kateřina Muškova   
Login: xmusko00  

## Popis
Server komunikující HTTP protokolem, který zajišťuje překlad doménových jmen. Server podporuje operace GET a POST. 

## Příklad použití
### Spuštení serveru
make run PORT=[port number]

### Zaslání dotazu
* GET
```bash
curl --data-binary @queries.txt -X POST http://localhost:[port number]/dns-query
www.fit.vutbr.cz:A=147.229.9.23
www.google.com:A=172.217.23.196
147.229.14.131:PTR=dhcpz131.fit.vutbr.cz
ihned.cz:A=46.255.231.42
```
* POST
```bash
curl localhost:/resolve?name=www.fit.vutbr.cz&type=A
www.fit.vutbr.cz:A=147.229.9.23
```


## Způsob implementace
Řešení je implementováno v jazyce Python s použitím knihovny socket. 

## Struktura programu
Po spuštění programu a vyhodnocení argumentů je spuštěn Server, který předává požadavek Responderu.

#### Třída Server
Obstarává TCP komunikaci na daném portu.  
Metoda *run(port: int)* spouští celý TCP server, což znamená otevření welcome socketu, navazování spojení s klienty, přijetí jejich požadavků a odeslání odpovědí.

#### Třída Responder
Po zavolání metody *response(request_data: bytes)* se podle HTTP hlavičky rozhodne, zda se jedná o GET, nebo POST dotaz a dále se zavolá příslušná metoda *process_get()*, nebo *process_post()*.

Samotný překlad doménových jmen provádí metoda *translate_domain()*

V průběhu vyhodnocení se nastaví parametry *response_header* a *response_msg*, ze kterých se sestaví odesílaná odpověd.