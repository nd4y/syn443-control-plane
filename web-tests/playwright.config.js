import {defineConfig} from '@playwright/test';
export default defineConfig({testDir:'.',testMatch:'*.spec.js',workers:1,retries:0,timeout:120000,reporter:[['line'],['junit',{outputFile:'results.xml'}]],use:{baseURL:'http://127.0.0.1:17850',trace:'off',screenshot:'off',video:'off'},webServer:{command:'node fixture.js',url:'http://127.0.0.1:17850',reuseExistingServer:false,timeout:15000}});
