package jwt

import (
	"fmt"
	"sync"
	"time"

	"github.com/alrusov/misc"
)

//----------------------------------------------------------------------------------------------------------------------------//

type (
	// Элемент кэша для ранее созданных HTTP заголовков для метода JWT
	clientCacheElement struct {
		header string // Собственно заголовок
		exp    int64  // Время истечения (unixtime)
	}
)

var (
	cacheMutex        = new(sync.Mutex)
	clientsTokenCache = map[string]clientCacheElement{} // Кэш заголовков, ключ - см. сacheKey()
)

//----------------------------------------------------------------------------------------------------------------------------//

func init() {
	go func() {
		for {
			if !misc.Sleep(30 * time.Minute) {
				return
			}

			func() {
				cacheMutex.Lock()
				defer cacheMutex.Unlock()

				now := misc.NowUnix()

				for key, elm := range clientsTokenCache {
					if now > elm.exp {
						delete(clientsTokenCache, key)
					}
				}
			}()
		}
	}()
}

//----------------------------------------------------------------------------------------------------------------------------//

// Создание ключа для кэша из имени пользователя и секрета
func cacheKey(user string, secret string) string {
	return fmt.Sprintf("[%s].[%s]", user, secret)
}

//----------------------------------------------------------------------------------------------------------------------------//

// Создание HTTP заголовка для метода JWT для клиента из имени пользователя и секрета
func ClientHeader(user string, secret string, lifetime time.Duration) (headerString string, err error) {
	key := cacheKey(user, secret)

	cacheMutex.Lock()
	cached, exists := clientsTokenCache[key]
	cacheMutex.Unlock()

	if exists && (cached.exp > misc.NowUnix()+60) { // если токен будет еще валиден больше 60 секунд, то используем кэшированный заголовок
		headerString = cached.header
		return
	}

	// Создаем заголовок

	headerString, exp, err := MakeToken(user, secret, lifetime)
	if err != nil {
		return
	}

	headerString = "Bearer " + headerString

	// И кэшируем его

	cacheMutex.Lock()
	clientsTokenCache[key] = clientCacheElement{
		header: headerString,
		exp:    exp,
	}
	cacheMutex.Unlock()

	return
}

//----------------------------------------------------------------------------------------------------------------------------//
