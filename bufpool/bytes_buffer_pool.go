//     Copyright (C) 2020, IrineSistiana
//
//     This file is part of mos-chinadns.
//
//     mos-chinadns is free software: you can redistribute it and/or modify
//     it under the terms of the GNU General Public License as published by
//     the Free Software Foundation, either version 3 of the License, or
//     (at your option) any later version.
//
//     mos-chinadns is distributed in the hope that it will be useful,
//     but WITHOUT ANY WARRANTY; without even the implied warranty of
//     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//     GNU General Public License for more details.
//
//     You should have received a copy of the GNU General Public License
//     along with this program.  If not, see <https://www.gnu.org/licenses/>.

//     This file is a modified version from github.com/xtaci/smux/blob/master/alloc.go f386d90
//     license of smux: MIT https://github.com/xtaci/smux/blob/master/LICENSE

package bufpool

import (
	"bytes"
	"sync"
)

var (
	defaultBytesBufPool = sync.Pool{
		New: func() interface{} {
			return new(bytes.Buffer)
		},
	}
)

func AcquireBytesBuf() *bytes.Buffer {
	return defaultBytesBufPool.Get().(*bytes.Buffer)
}

func ReleaseBytesBuf(buf *bytes.Buffer) {
	buf.Reset()
	defaultBytesBufPool.Put(buf)
}
