import { Component, OnInit } from '@angular/core';
import { FileSystemService } from '../providers/filesystem.service';

@Component({
  selector: 'app-home',
  templateUrl: './home.component.html',
  styleUrls: ['./home.component.scss']
})
export class HomeComponent implements OnInit {

  constructor(private _fsService: FileSystemService) { }

  ngOnInit() { }

  async openFileExample() {
    const resp = await this._fsService.readFile('Open File', 'Please select a file');
    console.log(resp);
  }

  async saveFileExample() {
    const filename = 'hello-world.txt';
    const msg = `Where would you like to save ${filename}?`;
    const encoder = new TextEncoder();
    const data = encoder.encode('Hello world!');
    const resp = await this._fsService.saveFile('Save File', msg, filename, data);
    console.log(resp ? resp : '[!] User cancelled operation');
  }

}
