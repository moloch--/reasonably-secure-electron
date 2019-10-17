/*
  Reasonably Secure Electron
  Copyright (C) 2019  Bishop Fox
  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.
  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <https://www.gnu.org/licenses/>.
--------------------------------------------------------------------------

This service is talks to the mTLS client and manages configs/etc.

*/

import { Injectable } from '@angular/core';
import * as base64 from 'base64-arraybuffer';

import { IPCService } from './ipc.service';
import { FileFilter } from 'electron';


export interface SaveFileReq {
  title: string;
  message: string;
  filename: string;
  data: string;
}


@Injectable({
  providedIn: 'root'
})
export class FileSystemService {

  private readonly NAMESPACE = 'fs';

  constructor(private _ipc: IPCService) { }

  async saveFile(title: string, message: string, filename: string, data: Uint8Array): Promise<string> {
    const resp = await this._ipc.request(`${this.NAMESPACE}_saveFile`, JSON.stringify({
      title: title,
      message: message,
      filename: filename,
      data: base64.encode(data),
    }));
    return resp;
  }

  async readFile(title: string, message: string, openDirectory?: boolean,
                 multiSelection?: boolean, filter?: FileFilter[]): Promise<string> {
    const resp = await this._ipc.request(`${this.NAMESPACE}_readFile`, JSON.stringify({
      title: title,
      message: message,
      openDirectory: openDirectory !== undefined ? openDirectory : false,
      multiSelection: multiSelection !== undefined ? multiSelection : false,
      filter: filter !== undefined ? filter : [{
        name: 'All Files',
        extensions: ['*']
      }],
    }));
    return resp ? JSON.parse(resp) : '';
  }

}
