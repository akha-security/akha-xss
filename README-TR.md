<div align="center">
<img width="1407" height="397" alt="banner" src="https://github.com/user-attachments/assets/8d9e3bd0-21cb-4adf-9804-987a5f404a20" />


  <br/>
  <h1>🎯 AKHA XSS Scanner</h1>
  <p><strong>AKHA-XSS Detection Framework</strong></p>
  <p>
    Güvenlik araştırmacıları, bug bounty avcıları ve DevSecOps süreçleri için özel olarak tasarlandı. AKHA, headless tarayıcı (Chromium) doğrulaması ve akıllı payload mutasyonları ile desteklenen, sıfıra yakın "false positive" (yanlış pozitif) oranıyla yüksek etkili Cross-Site Scripting (XSS) zafiyetlerini tespit eder.
  </p>

  <p>
    <a href="#özellikler">Özellikler</a> •
    <a href="#adaptif-payload-öğrenmesi-akhanın-farkı">Adaptif Öğrenme</a> •
    <a href="#nasıl-çalışır">Nasıl Çalışır?</a> •
    <a href="#kurulum">Kurulum</a> •
    <a href="#kullanım-kılavuzu">Kullanım</a> •
    <a href="#mimari">Mimari</a> •
    <a href="README.md">🇬🇧 English</a>
  </p>
</div>

---

## 📖 Genel Bakış

Geleneksel statik XSS tarayıcıları, devasa ve gürültülü test verisi (payload) listelerini körü körüne her bir uç noktaya (endpoint) gönderir. Bu yaklaşım IP adresinizin engellenmesine, veritabanlarının çöp verilerle dolmasına ve can sıkıcı derecede yüksek "false positive" oranlarına yol açar.

**AKHA, bu sürece kökten farklı bir yaklaşım getirir.** Tıpkı otomatikleştirilmiş bir Uygulama Güvenliği Mühendisi gibi hareket eden AKHA, **"Önce Sonda" (Probe-First) metodolojisini** kullanır. Herhangi bir sömürü (exploit) girişiminden önce, uygulamanın davranışını dinamik olarak analiz etmek, HTML içinde nereye enjekte olabildiğini bulmak (örneğin standart HTML, öznitelik içi, JavaScript değişkeni, CSS bloğu) ve aktif Web Uygulama Güvenlik Duvarları (WAF) ile sanitizasyon kurallarının haritasını çıkarmak için son derece spesifik, tamamen zararsız "sondalar" (canary probes) gönderir.

Ancak hedefin savunma mekanizmalarını tamamen anladıktan sonra, o anki bağlama özel, küçültülmüş ve optimize edilmiş bir payload listesi üretir ve hedefe yollar.

---

## ✨ Öne Çıkan Özellikler

### 🔍 Gelişmiş Tespit ve Modern Saldırı Yüzeyleri
* **Reflected & Stored XSS:** Karmaşık uygulama akışlarındaki kalıcı zafiyetleri tespit etmek için akıllı oturum izleme mekanizması.
* **Derin DOM-Tabanlı Analiz:** İstemci tarafı (client-side) DOM execution hatalarını bulmak için kullanıcı girdilerini (sinks) izler.
* **Out-of-Band (Blind) XSS:** Gecikmeli tetiklenen XSS'leri tespit etmek için OAST servisleri (Burp Collaborator, XSS Hunter veya kendi altyapınız) ile yerleşik entegrasyon.
* **Framework Spesifik Sink'ler:** **AngularJS CSTI** (İstemci Tarafı Template Enjeksiyonu) için özel test modülleri.
* **Modern Paradigmalar:** **GraphQL** uç noktaları, **WebSockets** iletişimleri ve **Mutation XSS (mXSS)** anomalileri için özel tarayıcı motorları.

### 🧠 Akıllı Parametre Keşfi (Smart Parameter Discovery)
* **Arjun Benzeri Diferansiyel Fuzzing:** Sadece statik kelime listelerine (wordlist) güvenmez. Normal yanıt modelleri oluşturur ve gizli parametreleri ortaya çıkarmak için diferansiyel grup testleri uygular.
* **Çoklu Vektör Enjeksiyonu:** Sadece GET/POST verilerini değil; RESTful yol (path) segmentlerini, HTTP başlıklarını (Headers) ve Çerezleri (Cookies) aynı anda test eder.

### 🛡️ Kurumsal Seviye ve DevSecOps Uyumu
* **Tarayıcı Motoru ile Kesin Doğrulama:** Bulunan payload'ları işletmek ve ekrana çıkan gerçek `alert` etkinliklerini yakalamak için Playwright (Headless Chromium) ile entegre çalışır. Bu sayede "Onaylandı" (Confirmed) seviyesindeki bulgularda %0 False Positive oranını garanti eder.
* **Adaptif Hız Sınırlandırması (Rate Limiting):** WAF'lar veya hedef sunucular HTTP 429/503 yanıtları vermeye başladığında otomatik olarak hızını düşürerek agresif banlanmalardan kurtulur.
* **Kesintisiz Entegrasyonlar:** CI/CD süreçleri için sonuçları JSON olarak çıktılayın, etkileyici HTML raporlar oluşturun ya da Webhook'lar üzerinden (Discord, Slack, Telegram) gerçek zamanlı uyarılar alın.
* **Oturuma Devam Edebilme (Resume):** Kesintiye uğrayan devasa taramalara tam olarak kaldığınız test noktasından devam edebilirsiniz.

### 🌐 Dinamik SPA Tarama (Playwright Destekli)
* **JavaScript-Render Edilen Keşif:** React, Vue, Angular gibi SPA framework'ü kullanan sitelerde klasik HTML ayrıştırıcılarının göremediği gizli endpoint'leri keşfetmek için otomatik olarak headless Chromium tarayıcısı başlatır.
* **Varsayılan olarak açıktır.** Sadece statik crawling istiyorsanız `--no-dynamic` ile kapatılabilir.

### ⚡ Asenkron Batch HTTP Motoru (httpx)
* **Yüksek Performanslı Ağ İstekleri:** Tek bir event loop üzerinden eş zamanlı istekler göndermek için arka planda `httpx.AsyncClient` kullanır. Go diliyle yazılmış Dalfox gibi araçlarla kıyaslanabilir hıza ulaşır.
* **Otomatik Fallback:** `httpx` yüklü değilse, motor otomatik olarak thread tabanlı `requests` kütüphanesine düşer — hata vermez, ayar gerekmez.

### 🔄 Akıllı Oturum ve Kimlik Doğrulama Yönetimi
* **Otomatik Yeniden Giriş (Auto Re-Auth):** Uzun taramalarda oturum süresi dolduğunda (HTTP 401/403), AKHA yapılandırılmış `--auth-url` bilgileriyle otomatik olarak yeniden giriş yapar ve taramaya ilerleme kaybetmeden devam eder.
* **Thread-Safe:** Paralel çalışan işçilerin aynı anda yeniden giriş yapmasını önlemek için kilit (lock) mekanizması kullanır.

### 🔀 IP Rotasyonu ve Proxy Havuzu
* **Round-Robin Proxy Rotasyonu:** `--proxy-list proxies.txt` ile bir proxy listesi verin, AKHA her istekte otomatik olarak sırayla farklı proxy kullanacaktır.
* **Otomatik Banlama ve Kurtarma:** Arka arkaya başarısız olan proxy'ler geçici olarak banlanır. 429/503 rate-limit algılandığında, AKHA anında bir sonraki sağlıklı proxy'ye geçer.

### 🕵️ Dahili Blind XSS OAST (Interactsh)
* **Sıfır Konfigrasyon OAST:** `--oast` bayrağı ile otomatik olarak bir Interactsh sunucusuna kayıt olun, benzersiz callback URL'leri oluşturun ve bunları Blind XSS payload'ları olarak enjekte edin.
* **Gerçek Zamanlı Uyarılar:** Arka planda çalışan bir yoklama (polling) thread'i DNS/HTTP callback'lerini izler ve bir Blind XSS tetiklendiği anda terminalinize kırmızı alarm basar.
* **Rapor Entegrasyonu:** Yakalanan tüm OAST callback'leri otomatik olarak tarama raporuna eklenir.

---

## 🧠 Adaptif Payload Öğrenmesi (AKHA'nın Farkı)

Çoğu tarayıcı, payload listesini statik bir sözlük gibi kullanır. AKHA böyle çalışmaz.

AKHA, gerçek tarama sonuçlarından sürekli öğrenir ve payload performans geçmişini `data/learning/payload_stats.json` dosyasında saklar.
Her payload için şu sayaçları izler:

* `success_count`: Payload'ın doğrulanmış bir bulguya dönüştüğü deneme sayısı.
* `fail_count`: Payload'ın başarısız olduğu deneme sayısı.
* `waf_blocked`: Payload'ın WAF tarafından engellendiği düşünülen deneme sayısı.

Bu veriler, yumuşatma (smoothing) ve WAF cezası içeren Bayesian tarzı bir skorlamaya girer. Böylece payload'lar statik sıraya göre değil, pratikte işe yarama olasılıklarına göre sıralanır.

AKHA ayrıca UCB yaklaşımıyla iki hedefi aynı anda dengeler:

* **Exploitation:** Geçmişte iyi çalışan payload'ları öne almak.
* **Exploration:** Az test edilmiş payload'ları da kontrollü şekilde denemek.

Pratik sonuç:

* Daha az boşa istek
* Çalışan payload ailesine daha hızlı yakınsama
* WAF yoğun hedeflerde daha akıllı test stratejisi
* Tek seferlik değil, domain/bağlam bazında zamanla güçlenen taramalar

---

## 🧠 Derinlemesine: AKHA Nasıl Çalışır? (Pipeline)

AKHA'nın gerçek gücü tasarladığı işlem hattıdır (pipeline). Keşfedilen her uç nokta ve parametre için AKHA aynı deterministik işlem akışını uygular:

### 1. 🐣 Sonda Aşaması (Canary Probing)
AKHA, uygulamanın içerisine zararsız ancak eşsiz bir alfanümerik metin (örn: `akhaPROBE123`) ve bunun yanına stratejik özel karakter bataryası (`<`, `>`, `"`, `'`, `/`, `(`, `)`) enjekte eder. Ardından HTTP yanıtını alarak bu girdinin yansıyıp yansımadığına, eğer yansıdıysa *nereye* yansıdığına bakar.

### 2. 🧩 Bağlam Haritalama (Context Mapping)
Sadece girdinin sayfada olması yeterli değildir. AKHA ayrıştırıcıları kullanarak DOM analizine girer:
* **HTML Gövdesi:** `<div>[PROBE]</div>`
* **HTML Özniteliği (Attribute):** `<input value="[PROBE]">`
* **JavaScript Bağlamı:** `<script>var x = "[PROBE]";</script>`
* **CSS Bağlamı:** `<style>body { color: [PROBE]; }</style>`
* **URL/Aksiyon Bağlamı:** `<a href="[PROBE]">`

### 3. 🛡️ Sanitizasyon ve WAF Profilleme
Gönderdiği sondadaki hangi özel karakterlerin hayatta kaldığını, hangilerinin URL/HTML encode edildiğini veya hangilerinin tamamen sunucu tarafından silindiğini analiz eden AKHA, gerçek zamanlı bir temizleme (sanitization) profili çıkarır. Örneğin, `<` karakterinin engellendiğini ama `"` (çift tırnak) karakterine izin verildiğini hemen idrak eder.

### 4. 🧮 Akıllı Payload Üretimi
AKHA payload veritabanına bağlanır ve **Adaptif Payload Zekasını** devreye sokar. Eğer bağlam bir JavaScript değişkeni ise ve çift tırnak (`"`) engellenirken tek tırnağa (`'`) izin veriliyorsa, dinamik olarak `'-alert(1)-'` gibi bir payload üretir. Benzer bağlamlarda veya WAF korumalarında geçmişte başarı göstermiş payload'ları seçmek için UCB algoritmalarını kullanır.

### 5. 🎯 Çok Aşamalı Doğrulama
Bir payload yansıdığında AKHA yürütme (execution) potansiyelini doğrular:
* **İşaretçi Taraması:** İşlenen DOM içerisindeki payload'un bıraktığı özel işaretçileri arar.
* **Ham Yansıma Eşleşmesi:** Kodu çalıştıracak kritik karakterlerin (>, ', vd.) sunucu kodlamasını (encoding) atlatıp atlatmadığından emin olur.
* **Tarayıcı Emülasyonu:** Eğer ayarlandıysa, motor Headless Chromium başlatır, payload'ı enjekte eder ve JavaScript event loop'unda `alert()` tetiklenip tetiklenmediğini denetler.

### 6. ⚖️ Güven Skorlaması (Confidence Scoring)
Bulgulara, doğrulama aşamasında geride bıraktıkları kanıtların gücüne dayanarak sofistike bir **Güven Skoru (%0-100)** atanır.

| Skor | Ciddiyet | Açıklama |
| :--- | :--- | :--- |
| **80 - %100** | **Onaylandı (Confirmed)** | Kodun kesinlikle yürütüldüğünün (execution) kanıtı. Headless tarayıcı doğrulaması alan ya da kusursuz ham yansıma sergileyen payload'lar. |
| **50 - %79** | **Potansiyel (Potential)** | Tehlikeli bir bağlamda güçlü bir yansıma gerçekleşti fakat otomatik sistem JavaScript'i tetikleyemedi. Uzman için manuel inceleme önerilir. |
| **0 - %49** | **Düşük (Low)** | Parçalı ya da çok zayıf bir yansıma algılandı. Framework'lerin yapısal savunmaları tarafından durdurulmuş olabilir, ancak referans olması adına loglanmıştır. |

---

## ⚙️ Kurulum

### Gereksinimler
- Python 3.9+
- pip

### Standart Kurulum
Hızlı koşan, CLI tabanlı, tarayıcı render'ı gerektirmeyen CI/CD otomasyonları ve testler için tavsiye edilir.
```bash
git clone https://github.com/akha-security/akha-xss.git
cd akha-xss
pip install -e .
```

### 🏆 Tam Kurulum (Önerilen)
Bu işlem, Playwright gereksinimlerini indirerek sıfır hata toleranslı "Execution Verifier" özelliğini (Tarayıcı Simülasyonu) devreye almanızı sağlar.
```bash
pip install -e .[browser]
playwright install chromium
```

---

## 🚀 Kullanım Kılavuzu

Program terminal/CLI üzerinde `akha-xss` komutu ile çalışır.

### Temel Tarama
```bash
# Tekil bir hedef uygulamanın yüksek hızlı taraması
akha-xss scan --url https://domain.com

# Birden fazla hedefi tarama
akha-xss scan --file targets.txt
```

### Tarama Profilleri (Derinlik - Hız Dengesi)
AKHA'nın parametre bulma agresifliğini ve test edilecek payload varyant sayısını kontrol edin.
```bash
# 🏎️ Hızlı: Minimum parametre fuzzing işlemi, yalnızca nokta atışı hedefe dönük payload'lar.
akha-xss scan --url https://domain.com --profile quick

# ⚖️ Dengeli (Varsayılan): Derin keşifler ve tarama süresi arasındaki optimal nokta.
akha-xss scan --url https://domain.com --profile balanced

# 🕵️ Derin: Oldukça ağır, geniş çaplı parametre keşfi ve yüksek mutasyonlu payload tespiti.
akha-xss scan --url https://domain.com --profile deep

# 💥 Agresif Mod: Thread'leri yükselt, SSL kontrollerini kapat, her şeyi hedef al.
akha-xss scan --url https://domain.com --deep-scan --aggressive
```

### Kimlik Doğrulama ve Başlıklar (Auth & Headers)
```bash
# Cookie (Çerez) Tabanlı Kimlik Doğrulama
akha-xss scan --url https://domain.com --cookie "SESSIONID=xyz123; UID=99"

# Bearer Token (JWT Auth)
akha-xss scan --url https://domain.com --bearer-token "eyJhbGci..."

# Özel Başlık Kullanımı
akha-xss scan --url https://domain.com -H "X-Custom-Auth: supersecret"
```

### Auth Plugin Entegrasyon Rehberi

Basit `--auth-url` + `--auth-data` akışı yetersiz kaldığında auth plugin kullanın.

* `csrf-preflight`: Her istekte değişen CSRF token kullanan klasik form login akışları için idealdir.
* `bearer-refresh`: Access token süresi dolan API oturumlarında token yenileme için idealdir.

Önerilen akış:
1. Önce temel auth bayrakları ile başlayın (`--auth-url`, `--auth-data`, `--cookie`, `--bearer-token`).
2. Login ilk başta başarılı ama ileride 401/403 alıyorsanız `--auth-plugin` açın.
3. Sadece gerekli alanlarla `--auth-plugin-options` verin.

Örnek (CSRF form login):
```bash
akha-xss scan --url https://domain.com \
  --auth-url https://domain.com/login \
  --auth-data '{"username":"admin","password":"pass"}' \
  --auth-plugin csrf-preflight \
  --auth-plugin-options '{"preflight_url":"https://domain.com/login","token_fields":["csrf_token","_token"]}'
```

Örnek (Bearer refresh akışı):
```bash
akha-xss scan --url https://api.domain.com \
  --bearer-token "eyJhbGci..." \
  --auth-plugin bearer-refresh \
  --auth-plugin-options '{"refresh_url":"https://api.domain.com/auth/refresh","payload_json":{"refresh_token":"xyz"}}'
```

Operasyon ipuçları:
* Auth plugin kullanırken `--no-reauth` kapalı kalsın.
* Login drift riskini azaltmak için plugin option payload'ını minimum tutun.
* JSON rapordaki `auth` alanından yaşam döngüsünü kontrol edin (`reauth_count`, `auth_failures`, `last_event`).

Hızlı sorun giderme:
* Belirti: Login ilk denemede başarısız oluyor.
  Çözüm: `csrf-preflight` ve `token_fields` ile doğru CSRF alan adlarını verin.
* Belirti: Taramanın ortasında sürekli 401/403 dönüyor.
  Çözüm: `bearer-refresh` plugin'i ile `refresh_url` ve refresh payload'ını ekleyin.
* Belirti: Plugin açık ama reauth sayısı artmıyor.
  Çözüm: JSON rapordaki `auth.last_event` alanını kontrol ederek plugin reason bilgisini doğrulayın.

### Kapsam Belirleme (Scope Filtering)
Motorun yönetim panellerinde veya çıkış/silme URL'lerinde sonsuza dek kaybolmasını engelleyin.
```bash
akha-xss scan --url https://domain.com \
              --include "/api/v1/.*" \
              --exclude "/logout" --exclude "/admin/.*"
```

### Modül Kontrolü
Saldırı alanını istediğiniz spesifik bölgelere odaklayın.
```bash
# API Odaklı Tarama (Sadece POST gövdelerini, JSON verilerini ve Başlıkları test eder)
akha-xss scan --url https://api.domain.com --api-mode --test-post

# Sadece WebSocket ve Başlık Vektörlerini tara, Ağır DOM testlerini devre dışı bırak
akha-xss scan --url https://domain.com --websockets --test-headers --no-dom-xss
```

### Blind XSS Konfigürasyonu
Site yetkilisinin haftalar sonra admin panelini açması durumunda bile, enjekte edilmiş payload ateşlenip direkt size uyarı yollasın istiyorsanız:
```bash
# Kendi collaborator / XSS Hunter URL'inizi kullanın
akha-xss scan --url https://domain.com --blind-xss-url https://your-id.oastify.com

# Veya dahili Interactsh OAST istemcisini kullanın (sıfır konfigürasyon)
akha-xss scan --url https://domain.com --oast
```

### Proxy Rotasyonu ve Gizlilik (Stealth)
IP banlanmalarından ve WAF rate-limit engellerinden kaçınmak için proxy havuzu kullanın.
```bash
# Tekli proxy (örn: Burp Suite)
akha-xss scan --url https://domain.com --proxy http://127.0.0.1:8080

# Proxy havuzu rotasyonu (dosyada satır başına bir proxy URL)
akha-xss scan --url https://domain.com --proxy-list proxies.txt
```

### Oturum Yönetimi (Session Management)
```bash
# Uzun taramalarda oturum düştüğünde otomatik yeniden giriş
akha-xss scan --url https://domain.com \
              --auth-url https://domain.com/login \
              --auth-data '{"username": "admin", "password": "pass"}'

# Otomatik yeniden girişi devre dışı bırak
akha-xss scan --url https://domain.com --no-reauth
```

### Raporlama ve Otomasyon Uyarıları
```bash
# Otomatik zafiyet yönetim platformları için saf JSON çıktısı üret
akha-xss scan --url https://domain.com --format json --json-output results.json

# Sistem "Yüksek Güvenilir" (High Confidence) bir açık yakaladığında direkt Discord Webhook ateşle
akha-xss scan --url https://domain.com \
              --webhook-url https://discord.com/api/webhooks/your-hook \
              --webhook-platform discord
```

---

## 🚀 Temel Yetkinlikler

AKHA, adaptif tarama yeteneklerinin tamamını varsayılan ürün kabiliyeti olarak sunar.

### Doğrulama ve Kanıt Kalitesi
* Confidence skorlamasında **yapısal DOM kanıtı** ve **tekrarlanabilirlik oranı** kullanılır.
* Triyaj için confidence yanında **exploitability score** raporlanır.
* Chromium yanında **Firefox execution verification** desteği bulunur.
* Bulgular ve raporlar **browser evidence matrix** içerir.

### Keşif ve Önceliklendirme
* Crawl/discovery akışında **risk bazlı endpoint önceliklendirme** kullanılır.
* Semantik olarak eşdeğer endpoint'ler için **kanonik tekilleştirme** uygulanır.
* Sınırlı geçiş bütçesi ile **stateful SPA discovery** desteklenir.
* **Discovery profile** seçenekleri sunulur (`auto`, `anonymous`, `authenticated`, `admin`).

### WAF ve Trafik Adaptasyonu
* Global sınırlara ek **host** ve **path** bazlı throttling uygulanır.
* Proxy havuzu **karantina + cooldown sonrası geri kazanım** döngüsünü destekler.
* **Challenge-aware target backoff** ile adaptif ceza uygulanır.
* Yerleşik **endpoint sınıfı backoff profilleri** bulunur (`default`, `api_read`, `api_write`, `auth`).
* Config/CLI üzerinden profil **override** desteği vardır.
* WAF tespit çıktısı zengin **confidence_score** ve **evidence** alanları içerir.

### Payload Zekası
* Learning motoru **başarısızlık nedeni sınıflandırması** tutar (`blocked`, `encoded`, `stripped`, `inert`).
* Payload sıralaması **endpoint profiline duyarlı UCB** yaklaşımıyla yapılır.
* **Grammar-guided minimal payload** üretimi kısa ve bağlama uygun adayları öne alır.
* **Benzerlik tabanlı warm-start** cold-start etkisini azaltır.
* Learning çıktılarında toplu **failure_reasons** raporlanır.

### Performans, Ölçek ve Gözlemlenebilirlik
* Tarama için **sert bütçe sınırları** (süre, toplam istek, toplam payload denemesi) tanımlanabilir.
* **Parametre başına** ve **endpoint başına** payload limitleri uygulanır.
* **Lease/ack tabanlı dağıtıma hazır task queue** modeli ile worker tarzı resume akışı desteklenir.
* Uzun taramalar için **periyodik resume checkpoint** desteği vardır.
* Raporlar **HTTP telemetry** içerir (latency yüzdelikleri, durum kodu dağılımı, havuz kullanımı).
* Bütçe baskısında **otomatik fallback** ile ağır modüller devreden çıkarılabilir.
* Worker planlamasında **dinamik task lease** ve **retry sonrası dead-letter** davranışı desteklenir.
* Raporlarda **modül bazlı zaman metrikleri** bulunur.

### Kalite ve Sürüm Korumaları
* **Pipeline contract testleri** analyzer/exploiter/reporter sınırlarını doğrular.
* **Golden target regression fixture** ile rapor çıktısı kararlı tutulur.
* Raporlarda **evidence chain** alanları yer alır (probe -> reflection -> verification -> execution).
* Güvenli varsayılanlar için **scope guardrail** mekanizması bulunur.
* Baseline kıyaslı CI kalite kapısı için `tools/quality_gate.py` kullanılır.

### Öne Çıkan `scan --help` Parametreleri

```bash
# Doğrulama
--execution-verify-firefox

# Kimlik doğrulama
--auth-plugin csrf-preflight
--auth-plugin-options '{"preflight_url":"https://domain.com/login"}'

# Keşif
--no-stateful-spa
--spa-state-budget 8
--discovery-profile auto
--no-risk-prioritization
--risk-top-k 300

# WAF ve trafik adaptasyonu
--no-per-host-rate-limit
--no-per-path-rate-limit
--path-rate-multiplier 0.75
--proxy-cooldown-seconds 60
--no-endpoint-backoff-profiles
--endpoint-backoff-overrides '{"auth": {"penalty_mult": 2.2}}'

# Payload zekasi
--no-payload-failure-taxonomy
--no-payload-context-bandit
--no-payload-minimal-grammar
--no-payload-similarity-warm-start
--ucb-exploration 1.4
--payload-context-weight 0.25
--payload-encoding-weight 0.15
--payload-waf-weight 0.10

# Bütçe ve planlama
--max-scan-seconds 900
--max-requests 20000
--max-payloads 8000
--max-payloads-per-param 20
--max-payloads-per-endpoint 120
--task-lease-seconds 120
--task-worker-id worker-a
--no-distributed-task-queue
--resume-checkpoint-seconds 30
--no-dynamic-task-lease
--task-max-retries 3
--no-budget-auto-fallback
--budget-fallback-trigger 0.85

# Güvenlik
--no-scope-guard
--scope-guard-max-pages 8000
```

### Örnek: İleri Seviye Adaptif Tarama

```bash
akha-xss scan --url https://domain.com \
  --profile deep \
  --execution-verify-firefox \
  --discovery-profile authenticated \
  --spa-state-budget 12 \
  --risk-top-k 500 \
  --path-rate-multiplier 0.6 \
  --proxy-cooldown-seconds 120 \
  --no-payload-context-bandit \
  --no-payload-similarity-warm-start \
  --max-scan-seconds 1800 \
  --max-requests 50000 \
  --resume-checkpoint-seconds 30 \
  --endpoint-backoff-overrides '{"auth":{"penalty_mult":2.4,"backoff_extra":6}}'

### CI Kalite Kapısı Örneği

```bash
python tools/quality_gate.py \
  --baseline output/baseline_report.json \
  --current output/scan_report_latest.json \
  --max-duration-regression 20 \
  --max-request-regression 25 \
  --min-confirmed-ratio 40 \
  --max-p95-latency-regression 30 \
  --max-confirmed-ratio-drop 20
```

### Örnek: Auth Plugin Akışı

```bash
# CSRF preflight destekli form login
akha-xss scan --url https://domain.com \
  --auth-url https://domain.com/login \
  --auth-data '{"username":"admin","password":"pass"}' \
  --auth-plugin csrf-preflight \
  --auth-plugin-options '{"preflight_url":"https://domain.com/login","token_fields":["csrf_token","_token"]}'

# API oturumları için bearer token yenileme plugin'i
akha-xss scan --url https://api.domain.com \
  --bearer-token eyJhbGci... \
  --auth-plugin bearer-refresh \
  --auth-plugin-options '{"refresh_url":"https://api.domain.com/auth/refresh","payload_json":{"refresh_token":"xyz"}}'
```

---

## 🏛️ Mimari ve Genişletilebilirlik 

AKHA, modüler yazılım tasarım prensiplerine sıkı sıkıya bağlı olarak kodlanmıştır. Kurumsal güvenlik mühendisleri veya Ar-Ge ekipleri sisteme çok rahat bir biçimde yeni modüller ekleyebilir.

* `akha.core`: Orkestrasyon katmanıdır. ThreadPool'ları dağıtmayı, adaptif ağ trafiği süren `HTTPClient`'ı (asenkron httpx batch desteği, proxy rotasyonu ve otomatik yeniden giriş mekanizması dahil) ve oturum tabanlı dosyaya kaydet/devam et logiklerini içerir.
* `akha.modules.xss`: Bağlama duyarlı sömürü motorlarının (`XSSEngine`, `Injector`, `SmartValidator`, `Verifier`) bulunduğu çekirdektir.
* `akha.modules.interactsh_client`: Otomatik Blind XSS callback tespiti için dahili Interactsh OAST istemcisi.
* `akha.payloads`: Yerel SQLite/JSON bazlı payload kütüphaneleri, WAF atlatma mutasyon kütüphaneleri ve zeka motorunu (learning engine) barındırır.

Kendi sızma testi altyapınıza yeni bir motor (örn: SSRF veya SQLi modülü) inşa etmek isterseniz,  `akha.core.pipeline` altındaki abstract `Pipeline` sınıfını extend etmeniz ve komut satırı plugin kaydını girmeniz yeterli olacaktır.

---

## ⚠️ Yasal Uyarı ve Etik Sorumluluk

**AKHA XSS Scanner, yalnızca yasal olarak yetkilendirilmiş olduğunuz eğitim amaçlı araştırmalar ve pro-aktif profesyonel güvenlik testleri (sızma / penetrasyon testleri) için geliştirilmiştir.**

* Kendinize ait olmayan veya sarih, yazılı ve yasal bir sözleşmeyle yetkilendirilmediğiniz ağlar, otomasyonlar ve dijital işletmeler üzerinde **kesinlikle kullanmayınız**.
* `--deep-scan` ve parametre fuzzing mekanizmalarının son derece agresif doğası göz önüne alındığında, bu aracın üretim (production) sistemlerinde kullanılması "Hizmet Engelleme" (DoS) durumlarına, amaç dışı/istemsiz veritabanı değişikliklerine veya sistem operasyonlarında tam kesintiye neden olabilir.
* Testlerinizi mümkün olan her koşulda "Staging" veya "Pre-Prod" (canlıya çıkmadan önceki test ortamları) sistemlerinde gerçekleştiriniz. 
* Olası dikkatsiz kullanımlar, doğuracağı hasarlar, veri kayıpları ya da projenin kanun dışı amaçlarla istismar edilmesi durumlarında araç geliştiricileri veya projede emeği geçen hiçbir geliştirici hiçbir koşulda, net bir şekilde hukuki ya da ahlaki herhangi bir sorumluluğu **üstlenmemektedir.** Tüm potansiyel riskleri şahıs / kurum düzeyinde kabul edersiniz. 

---

<div align="center">
<b>Güvenlik camiası için ❤️ ile geliştirildi. MIT Lisansı altındadır.</b>
</div>
