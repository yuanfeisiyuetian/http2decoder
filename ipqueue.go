package main

import (
	"container/list"
)

//map init and new a list
func Newlist() *list.List {
	Sameiplist = make(map[vkey]*Packlist)
	Sameportlist = make(map[hkey]*Packlist)
	return list.New()
}

//add element in tail
func Addtail(list *list.List, element *Packlist) *list.List {
	if list.Len() == limit {
		e := list.Remove(list.Front())
		if t, ok := e.(*Packlist); ok {
			if t.isv {
				delete(Sameiplist, t.vkey)
			}
			if t.ish {
				delete(Sameportlist, t.hkey)
			}
		}
	}
	list.PushBack(element)
	return list
}

//put the used element in the tail position
func adjustpositon(list *list.List, element *list.Element) *list.List {
	list.MoveToBack(element)
	return list
}

//delete element
func del(list *list.List, element *list.Element) {
	list.Remove(element)
}

//get the packlist position in list
func get(list *list.List, element *Packlist) *list.Element {
	for p := list.Front(); p != list.Back(); p = p.Next() {
		if p.Value == element {
			return p
		}
	}
	return nil
}
