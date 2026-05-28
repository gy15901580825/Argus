module.exports = {
  apps: [
    {
      name: 'argus-frontend',
      script: './node_modules/next/dist/bin/next',
      args: 'start',
      cwd: '/home/ubuntu/workspace/frontend',
      instances: 1,
      autorestart: true,
      watch: false,
      max_memory_restart: '1G',
      env: {
        NODE_ENV: 'production',
        PORT: 3000,
        // Casdoor OAuth Configuration
        CASDOOR_CLIENT_ID: '<change-me>',
        CASDOOR_CLIENT_SECRET: '<change-me>',
        CASDOOR_SERVER_URL: 'https://api.example.com',
        CASDOOR_ORGANIZATION_NAME: '<your-org>',
        CASDOOR_APP_NAME: 'argus',
        // Built-in Organization
        CASDOOR_BUILTIN_CLIENT_ID: '<change-me>',
        CASDOOR_BUILTIN_CLIENT_SECRET: '<change-me>',
      },
      error_file: './logs/pm2-error.log',
      out_file: './logs/pm2-out.log',
      log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
    },
  ],
}
