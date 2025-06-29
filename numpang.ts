import * as fs from "fs";

const url = 'http://localhost:8000/api/v1';
const headers = {
    Accept: '*/*',
    'User-Agent': 'Thunder Client (https://www.thunderclient.com)',
    Authorization: 'Bearer f6UbAijkLvUdUhXd3DlxZF4rQq2KEoqLpmibZTzqa03910b3',
    'Content-Type': 'application/json'
};

const project_uuid = "y4g48kkkg0008kc04s04c4c8";
const server_uuid = "yossgw80cgg8ws888ww8wkoo";
const domain = "maxgpt.id";
const environment_uuid = "ekokk88csg0o8cgkc0w0g00o";

const docker_compose_raw = `
services:
  n8n:
    image: docker.n8n.io/n8nio/n8n
    environment:
      - SERVICE_FQDN_N8N_5678
      - 'N8N_EDITOR_BASE_URL=\${SERVICE_FQDN_N8N}'
      - 'WEBHOOK_URL=\${SERVICE_FQDN_N8N}'
      - 'N8N_HOST=\${SERVICE_URL_N8N}'
      - 'GENERIC_TIMEZONE=\${GENERIC_TIMEZONE:-Europe/Berlin}'
      - 'TZ=\${TZ:-Europe/Berlin}'
    domain: test-jefripunza.${domain}
    volumes:
      - 'n8n-data:/home/node/.n8n'
    healthcheck:
      test:
        - CMD-SHELL
        - 'wget -qO- http://127.0.0.1:5678/'
      interval: 5s
      timeout: 20s
      retries: 10
`;
const base64Encoded = Buffer.from(docker_compose_raw).toString('base64');
let body = {
    project_uuid,
    server_uuid,
    environment_name: domain,
    environment_uuid,
    docker_compose_raw: base64Encoded,
    name: "string",
    instant_deploy: false,
};

const delay = (ms: number) => new Promise<void>(res => setTimeout(res, ms));

(async () => {
    try {
        let response = await fetch(`${url}/applications/dockercompose`, {
            method: 'POST',
            headers,
            body: JSON.stringify(body),
        });
        let data = await response.json();
        const uuid = data.uuid;
        console.log("UUID:", uuid);
        await delay(1000 * 2);

        // update name and domains
        response = await fetch(`${url}/services/${uuid}`, {
            method: 'PATCH',
            headers,
            body: JSON.stringify({
                project_uuid: project_uuid,
                server_uuid: server_uuid,
                environment_name: domain,
                environment_uuid,
                name: `n8n-${uuid}-jefripunza`,
                docker_compose_raw: base64Encoded,
                instant_deploy: true,
                // docker_compose_domains: [
                //     {
                //         "n8n": {
                //             "domain": "https://media.betterkpi.com"
                //         }
                //     }
                // ],
                // urls: [
                //     {
                //         "name": "n8n",
                //         "url": `${uuid}-jefripunza.${domain}`
                //     },
                // ],
            })
        })
        data = await response.json();
        if (data?.domains && data.domains.length > 0) {
            console.log("Deployed ...");
        } else {
            // delete service
            await fetch(`${url}/services/${uuid}`, {
                method: 'DELETE',
                headers,
            });
        }
        console.log(data);
    } catch (error) {
        console.error(error);
    }
})();
