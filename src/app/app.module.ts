import 'reflect-metadata';
import '../polyfills';

import { BrowserModule } from '@angular/platform-browser';
import { NgModule } from '@angular/core';
import { FormsModule } from '@angular/forms';

import { SharedModule } from './shared/shared.module';
import { AppRoutingModule } from './app-routing.module';
import { HomeModule } from './home/home.module';

import { IPCService } from './providers/ipc.service';
import { FileSystemService } from './providers/filesystem.service';

import { AppComponent } from './app.component';


@NgModule({
  declarations: [AppComponent],
  imports: [
    BrowserModule,
    FormsModule,

    SharedModule,
    HomeModule,
    AppRoutingModule,
  ],
  providers: [IPCService, FileSystemService],
  bootstrap: [AppComponent]
})
export class AppModule {}
