# net-list

高性能IP路由表匹配库，内存对齐，二分搜索，仅占用一个堆对象，匹配过程零堆占用。

---

## 从string reader批量加载CIDR格式的IP

    NewListFromReader(reader io.Reader) (*List, error)

## 从文件批量加载CIDR格式的IP

    NewListFromFile(file string) (*List, error) 

## 逐一添加

	l := NewList()

    // 从 net.IP 添加

	ip := net.IP{222, 222, 222, 222}
	ipv6, err := Conv(ip)
	if err != nil {
        ...
	}
	n := NewNet(ipv6, 24+96) // 相当于 222.222.222.222/24
	l.Append(n)

    // 从 string 添加

    n, err = ParseCIDR("1.2.3.4/24")
    if err != nil {
        ...
	}
    l.Append(n)

    ...

    l.Sort()  // 添加完后需对列表排序才能匹配Contains，否则Contains()会panic


## 匹配 Contains

    l := NewList()
    ...

    ip := net.IP{111, 111, 111, 111}
	ipv6, err := Conv(ip)
	if err != nil {
        ...
	}

    l.Sort() // 调用Contains()前l必需是sorted状态
    l.Contains(ipv6) // true or false