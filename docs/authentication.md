# Optional OTP/MFA — Հայերեն / Русский / English

## Հայերեն

Սուրոյի մուտքը լռելյայն պահանջում է միայն օգտանուն և գաղտնաբառ։ OTP-ն մեկանգամյա կոդ է, իսկ MFA-ն՝ մի քանի գործոնով նույնականացում։ TOTP հավելվածը գաղտնի բանալուց և ընթացիկ ժամից ստեղծում է կարճաժամկետ կոդ։ Այն կարող է աշխատել առանց ինտերնետի, սակայն հեռախոսի և սերվերի ժամերը պետք է ճիշտ լինեն։ Գաղտնի բանալին չպետք է ուղարկել չաթով կամ ներառել գրանցամատյաններում։

Կարգավորելու համար բացեք Կարգավորումներ → MFA, ստեղծեք կարգավորման տվյալները, ավելացրեք դրանք վստահելի նույնականացման հավելվածում և հաստատեք ընթացիկ կոդով։ Եթե MFA-ն պարտադիր չէ, մուտքի էջում բացեք կամընտիր OTP դաշտը՝ կոդն օգտագործելու համար։ Արդեն պահպանված գաղտնի բանալիները չեն ջնջվում։ Կոդի նույն ժամանակային քայլը կրկնակի չի ընդունվում։

Պարտադիր պաշտպանությունը միացնելուց առաջ փորձարկեք հաշիվը և պահպանեք սերվերի տեղային վահանակով վերականգնման հասանելիությունը։ `.env`-ում `MFA_LOGIN_REQUIRED=true`-ը պահանջում է կոդ այն հաշիվների մուտքի ժամանակ, որոնց համար TOTP-ն կարգավորված է։ `MFA_REQUIRED=true`-ը արտոնյալ գործողությունների համար պահանջում է վերջին տասը րոպեի հաստատում։ Երկուսն էլ լռելյայն `false` են։ Վերջին տարբերակը միացնելուց առաջ բոլոր անհրաժեշտ ադմինիստրատորների համար կարգավորեք TOTP։ Փոփոխությունից հետո վերաստեղծեք API և worker բեռնարկղերը։

Հեռախոսի կորստի դեպքում սերվերի լիազորված տեղային վահանակից գործարկեք `docker compose exec backend python -m app.cli recover-admin --username admin`։ Հրամանի ճշգրիտ տարբերակները ստուգեք `--help`-ով։ Վերականգնման ընթացքում գաղտնաբառը մուտքագրեք անվտանգ հարցման միջոցով։ Ստուգեք աուդիտը և նորից կարգավորեք TOTP-ն։ Օգտատիրոջ կամ MikroTik-ի հավաստագրերի ստուգումը այս կարգավորումներից չի թուլանում։

## Русский

По умолчанию для входа в Suro нужны только имя пользователя и пароль. OTP — одноразовый код; MFA — проверка несколькими факторами. Приложение TOTP вычисляет короткоживущий код из секретного ключа и текущего времени. Интернет ему не нужен, но часы телефона и сервера должны быть точными. Не отправляйте секретный ключ в переписке и не сохраняйте его в журналах.

Откройте Настройки → MFA, создайте данные настройки, добавьте их в доверенное приложение аутентификации и подтвердите текущим кодом. Для необязательного входа с OTP раскройте соответствующее поле на странице входа. Существующие секреты сохраняются. Один временной шаг кода нельзя успешно использовать повторно.

Перед обязательным включением проверьте вход и доступ к локальной консоли восстановления. `MFA_LOGIN_REQUIRED=true` в `.env` требует код при входе для аккаунтов, где TOTP уже настроен. `MFA_REQUIRED=true` требует подтверждение не старше десяти минут для привилегированных операций. Оба параметра по умолчанию равны `false`. Перед вторым параметром настройте TOTP для всех нужных администраторов. После изменения пересоздайте контейнеры API и worker.

При потере телефона используйте авторизованную локальную консоль сервера: `docker compose exec backend python -m app.cli recover-admin --username admin`. Проверьте точные параметры через `--help`. Вводите новый пароль через защищенный запрос, проверьте аудит и настройте TOTP заново. Эти настройки не ослабляют сертификаты агентов и проверку TLS MikroTik.

## English

Suro defaults to username/password login. OTP means a one-time password; MFA checks more than one authentication factor. A TOTP app derives a short-lived code from a secret and the current time. It can operate offline, but the phone and server clocks must be accurate. Do not send its secret in chat or put it in logs.

Open Settings → MFA, generate setup data, add it to a trusted authenticator, and confirm with its current code. For optional OTP login, expand the login page's OTP field. Existing secrets remain usable. A successful time step cannot be replayed.

Before enforcing MFA, test the account and retain authorized local-console recovery. In `.env`, `MFA_LOGIN_REQUIRED=true` requires a code at login for accounts with TOTP configured. `MFA_REQUIRED=true` requires verification within ten minutes for privileged operations. Both default to false. Configure TOTP for every necessary administrator before enabling the second flag. Recreate API/worker containers after changing environment settings.

If the phone is lost, use the authorized server console: `docker compose exec backend python -m app.cli recover-admin --username admin`. Check precise options with `--help`. Enter the new password through the interactive prompt, inspect audit records, and configure TOTP again. These flags do not weaken agent certificate authentication or MikroTik TLS validation.
