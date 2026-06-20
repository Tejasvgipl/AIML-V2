FROM nginx:1.25-alpine
COPY index.html /usr/share/nginx/html/index.html
COPY enhance.css /usr/share/nginx/html/enhance.css
COPY theme.css /usr/share/nginx/html/theme.css
# Optional brand logo: any logo.* you add here gets served (drop frontend/logo.png)
COPY logo* /usr/share/nginx/html/
COPY nginx.conf /etc/nginx/conf.d/default.conf
