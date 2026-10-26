import { Component } from '@angular/core';
import { capitalize, template, omit } from 'lodash-es';
@Component({ selector: 'app-root', template: '<h1>{{ title }}</h1>' })
export class App { title = template('<%= a %>')(omit({ a: capitalize('hello'), b: 1 }, ['b'])); }
