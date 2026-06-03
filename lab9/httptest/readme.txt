HTTP DAEMON TEST SITE
=====================
Ten plik służy do testowania obsługi typu MIME text/plain przez serwer HTTP.

Serwer powinien zwrócić ten plik z nagłówkiem:
  Content-Type: text/plain

Typy MIME obsługiwane przez serwer:
  text/html          - pliki .html
  text/plain         - pliki .txt   <-- ten plik
  text/css           - pliki .css
  application/javascript - pliki .js
  image/jpeg         - pliki .jpg / .jpeg
  image/png          - pliki .png
  image/gif          - pliki .gif

Struktura katalogu testowego:
  index.html                  (text/html)
  readme.txt                  (text/plain)
  styles/style.css            (text/css)
  scripts/script.js           (application/javascript)
  images/image1.jpg           (image/jpeg)
  images/image2.jpg           (image/jpeg)
  images/image.png            (image/png)
  images/animation.gif        (image/gif)
  documents/document.html     (text/html)

Aby przetestować serwer, uruchom go i otwórz w przeglądarce:
  http://localhost:<port>/

Możesz również użyć curl:
  curl -v http://localhost:<port>/readme.txt
  curl -v http://localhost:<port>/styles/style.css
  curl -v http://localhost:<port>/scripts/script.js
  curl -v http://localhost:<port>/images/image.png
  curl -v http://localhost:<port>/images/animation.gif
