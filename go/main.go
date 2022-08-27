package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	cmap "github.com/orcaman/concurrent-map/v2"

	_ "github.com/go-sql-driver/mysql"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/kaz/pprotein/integration/standalone"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"
)

var (
	ErrInvalidRequestBody       error = fmt.Errorf("invalid request body")
	ErrInvalidMasterVersion     error = fmt.Errorf("invalid master version")
	ErrInvalidItemType          error = fmt.Errorf("invalid item type")
	ErrInvalidToken             error = fmt.Errorf("invalid token")
	ErrGetRequestTime           error = fmt.Errorf("failed to get request time")
	ErrExpiredSession           error = fmt.Errorf("session expired")
	ErrUserNotFound             error = fmt.Errorf("not found user")
	ErrUserDeviceNotFound       error = fmt.Errorf("not found user device")
	ErrItemNotFound             error = fmt.Errorf("not found item")
	ErrLoginBonusRewardNotFound error = fmt.Errorf("not found login bonus reward")
	ErrNoFormFile               error = fmt.Errorf("no such file")
	ErrUnauthorized             error = fmt.Errorf("unauthorized user")
	ErrForbidden                error = fmt.Errorf("forbidden")
	ErrGeneratePassword         error = fmt.Errorf("failed to password hash") //nolint:deadcode

	nextBaseID int64 = 100000000000
	serverNum  int   = 1
)

const (
	DeckCardNumber      int = 3
	PresentCountPerPage int = 100

	SQLDirectory string = "../sql/"
)

type Handler struct {
	DB        *sqlx.DB
	PresentDB *sqlx.DB
}

func main() {
	go standalone.Integrate(":8888")

	rand.Seed(time.Now().UnixNano())
	time.Local = time.FixedZone("Local", 9*60*60)

	e := echo.New()
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: []string{"*"},
		AllowMethods: []string{http.MethodGet, http.MethodPost},
		AllowHeaders: []string{"Content-Type", "x-master-version", "x-session"},
	}))

	socket_file := "/tmp/app.sock"
	os.Remove(socket_file)

	l, err := net.Listen("unix", socket_file)
	if err != nil {
		e.Logger.Fatal(err)
	}

	// go runユーザとnginxのユーザ（グループ）を同じにすれば777じゃなくてok
	err = os.Chmod(socket_file, 0777)
	if err != nil {
		e.Logger.Fatal(err)
	}

	e.Listener = l

	serverNumStr := getEnv("ISUCON_SERVER_NUM", "1")
	serverNum, err = strconv.Atoi(serverNumStr)
	if err != nil {
		e.Logger.Fatalf("failed to connect to db: %v", err)
	}

	// connect db1
	dbx1, err := connectDB(false, "1")
	if err != nil {
		e.Logger.Fatalf("failed to connect to db1: %v", err)
	}
	defer dbx1.Close()
	dbx1.SetMaxIdleConns(1024) // デフォルトだと2
	dbx1.SetConnMaxLifetime(0) // 一応セット
	dbx1.SetConnMaxIdleTime(0) // 一応セット go1.15以上

	waitDB(dbx1)
	go pollDB(dbx1)
	//

	// connect db2
	dbx2, err := connectDB(false, "2")
	if err != nil {
		e.Logger.Fatalf("failed to connect to db2: %v", err)
	}
	defer dbx2.Close()
	dbx2.SetMaxIdleConns(1024) // デフォルトだと2
	dbx2.SetConnMaxLifetime(0) // 一応セット
	dbx2.SetConnMaxIdleTime(0) // 一応セット go1.15以上

	waitDB(dbx2)
	go pollDB(dbx2)
	//

	// initializes
	{
		// マスタ確認
		query := "SELECT * FROM version_masters WHERE status=1"
		if err := dbx1.Get(masterVersion, query); err != nil && err != sql.ErrNoRows {
			e.Logger.Fatalf("failed to read master vesrion: %w", err)
		}

		var sessions []Session
		query = "SELECT * FROM user_sessions WHERE deleted_at IS NULL"
		if err := dbx1.Select(&sessions, query); err != nil {
			e.Logger.Fatalf("failed to read sessions: %w", err)
		}
		for i := range sessions {
			userSessions.Set(sessions[i].SessionID, sessions[i])
		}

		var userDevices []UserDevice
		query = "SELECT * FROM user_devices"
		if err := dbx1.Select(&userDevices, query); err != nil {
		}
		for i := range userDevices {
			userDevicesSet.Set(getUserDevicesKey(userDevices[i].UserID, userDevices[i].PlatformID), struct{}{})
		}
	}

	// 問題の切り分け用
	http.DefaultTransport.(*http.Transport).MaxIdleConns = 0           // 無制限
	http.DefaultTransport.(*http.Transport).MaxIdleConnsPerHost = 1024 // 0にすると2になっちゃう
	http.DefaultTransport.(*http.Transport).ForceAttemptHTTP2 = true   // go1.13以上
	http.DefaultClient.Timeout = 5 * time.Second

	// setting server
	e.Server.Addr = fmt.Sprintf(":%v", "8080")
	h := &Handler{
		DB:        dbx1,
		PresentDB: dbx2,
	}

	// e.Use(middleware.CORS())
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{}))

	// utility
	e.POST("/initialize", initialize)
	e.GET("/health", h.health)

	// feature
	API := e.Group("", h.apiMiddleware)
	API.POST("/user", h.createUser)
	API.POST("/login", h.login)
	sessCheckAPI := API.Group("", h.checkSessionMiddleware)
	sessCheckAPI.GET("/user/:userID/gacha/index", h.listGacha)
	sessCheckAPI.POST("/user/:userID/gacha/draw/:gachaID/:n", h.drawGacha)
	sessCheckAPI.GET("/user/:userID/present/index/:n", h.listPresent)
	sessCheckAPI.POST("/user/:userID/present/receive", h.receivePresent)
	sessCheckAPI.GET("/user/:userID/item", h.listItem)
	sessCheckAPI.POST("/user/:userID/card/addexp/:cardID", h.addExpToCard)
	sessCheckAPI.POST("/user/:userID/card", h.updateDeck)
	sessCheckAPI.POST("/user/:userID/reward", h.reward)
	sessCheckAPI.GET("/user/:userID/home", h.home)

	// admin
	adminAPI := e.Group("", h.adminMiddleware)
	adminAPI.POST("/admin/login", h.adminLogin)
	adminAuthAPI := adminAPI.Group("", h.adminSessionCheckMiddleware)
	adminAuthAPI.DELETE("/admin/logout", h.adminLogout)
	adminAuthAPI.GET("/admin/master", h.adminListMaster)
	adminAuthAPI.PUT("/admin/master", h.adminUpdateMaster)
	adminAuthAPI.GET("/admin/user/:userID", h.adminUser)
	adminAuthAPI.POST("/admin/user/:userID/ban", h.adminBanUser)

	e.Logger.Infof("Start server: address=%s", e.Server.Addr)
	e.Logger.Error(e.StartServer(e.Server))
}

// adminMiddleware
func (h *Handler) adminMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		requestAt := time.Now()
		c.Set("requestTime", requestAt.Unix())

		// next
		if err := next(c); err != nil {
			c.Error(err)
		}
		return nil
	}
}

// initialized at /initialize and updated at POST /admin/master
var masterVersion = new(VersionMaster)
var masterVersionRWM = sync.RWMutex{}

// apiMiddleware
func (h *Handler) apiMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		requestAt, err := time.Parse(time.RFC1123, c.Request().Header.Get("x-isu-date"))
		if err != nil {
			requestAt = time.Now()
		}
		c.Set("requestTime", requestAt.Unix())

		masterVersionRWM.RLock()
		if masterVersion.MasterVersion != c.Request().Header.Get("x-master-version") {
			return errorResponse(c, http.StatusUnprocessableEntity, ErrInvalidMasterVersion)
		}
		masterVersionRWM.RUnlock()

		// check ban
		userID, err := getUserID(c)
		if err == nil && userID != 0 {
			isBan, err := h.checkBan(userID)
			if err != nil {
				return errorResponse(c, http.StatusInternalServerError, err)
			}
			if isBan {
				return errorResponse(c, http.StatusForbidden, ErrForbidden)
			}
		}

		// next
		if err := next(c); err != nil {
			c.Error(err)
		}
		return nil
	}
}

// deletedAt == nil
// initialized at main(), /initialize and updated at /user, /login
var userSessions = cmap.New[Session]()

// checkSessionMiddleware
func (h *Handler) checkSessionMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		sessID := c.Request().Header.Get("x-session")
		if sessID == "" {
			return errorResponse(c, http.StatusUnauthorized, ErrUnauthorized)
		}

		userID, err := getUserID(c)
		if err != nil {
			return errorResponse(c, http.StatusBadRequest, err)
		}

		requestAt, err := getRequestTime(c)
		if err != nil {
			return errorResponse(c, http.StatusInternalServerError, ErrGetRequestTime)
		}

		userSession, exist := userSessions.Get(sessID)
		if !exist {
			return errorResponse(c, http.StatusUnauthorized, ErrUnauthorized)
		}

		if userSession.UserID != userID {
			return errorResponse(c, http.StatusForbidden, ErrForbidden)
		}

		if userSession.ExpiredAt < requestAt {
			// async update
			go func() {
				query := "UPDATE user_sessions SET deleted_at=? WHERE session_id=?"
				if _, err = h.DB.Exec(query, requestAt, sessID); err != nil {
					c.Logger().Errorf("%w", err)
					//return errorResponse(c, http.StatusInternalServerError, err)
				}
			}()
			userSessions.Remove(sessID)
			return errorResponse(c, http.StatusUnauthorized, ErrExpiredSession)
		}

		// next
		if err := next(c); err != nil {
			c.Error(err)
		}
		return nil
	}
}

// checkOneTimeToken
func (h *Handler) checkOneTimeToken(token string, tokenType int, requestAt int64) error {
	tk := new(UserOneTimeToken)
	query := "SELECT * FROM user_one_time_tokens WHERE token=? AND token_type=? AND deleted_at IS NULL"
	if err := h.DB.Get(tk, query, token, tokenType); err != nil {
		if err == sql.ErrNoRows {
			return ErrInvalidToken
		}
		return err
	}

	if tk.ExpiredAt < requestAt {
		query = "UPDATE user_one_time_tokens SET deleted_at=? WHERE token=?"
		if _, err := h.DB.Exec(query, requestAt, token); err != nil {
			return err
		}
		return ErrInvalidToken
	}

	// 使ったトークンを失効する
	query = "UPDATE user_one_time_tokens SET deleted_at=? WHERE token=?"
	if _, err := h.DB.Exec(query, requestAt, token); err != nil {
		return err
	}

	return nil
}

var userDevicesSet = cmap.New[struct{}]()

func getUserDevicesKey(userID int64, viewerID string) string {
	return strconv.FormatInt(userID, 16) + viewerID
}

// checkViewerID
// 存在チェック
func (h *Handler) checkViewerID(userID int64, viewerID string) error {
	key := getUserDevicesKey(userID, viewerID)
	if !userDevicesSet.Has(key) {
		return ErrUserDeviceNotFound
	}
	return nil
}

var isBannedCache = cmap.New[bool]()

// checkBan
func (h *Handler) checkBan(userID int64) (bool, error) {
	id := strconv.Itoa(int(userID))

	isBanned, exist := isBannedCache.Get(id)
	if exist {
		return isBanned, nil
	}
	banUser := new(UserBan)
	query := "SELECT * FROM user_bans WHERE user_id=?"
	if err := h.DB.Get(banUser, query, userID); err != nil {
		if err == sql.ErrNoRows {
			isBannedCache.Set(id, false)
			return false, nil
		}
		return false, err
	}
	isBannedCache.Set(id, true)
	return true, nil
}

// getRequestTime リクエストを受けた時間をコンテキストからunixtimeで取得する
func getRequestTime(c echo.Context) (int64, error) {
	v := c.Get("requestTime")
	if requestTime, ok := v.(int64); ok {
		return requestTime, nil
	}
	return 0, ErrGetRequestTime
}

// loginProcess ログイン処理
func (h *Handler) loginProcess(tx *sqlx.Tx, txPresent *sqlx.Tx, userID int64, requestAt int64) (*User, []*UserLoginBonus, []*UserPresent, error) {
	user := new(User)
	query := "SELECT * FROM users WHERE id=?"
	if err := tx.Get(user, query, userID); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil, nil, ErrUserNotFound
		}
		return nil, nil, nil, err
	}

	// ログインボーナス処理
	loginBonuses, err := h.obtainLoginBonus(tx, userID, requestAt)
	if err != nil {
		return nil, nil, nil, err
	}

	// 全員プレゼント取得
	allPresents, err := h.obtainPresent(tx, txPresent, userID, requestAt)
	if err != nil {
		return nil, nil, nil, err
	}

	if err = tx.Get(&user.IsuCoin, "SELECT isu_coin FROM users WHERE id=?", user.ID); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil, nil, ErrUserNotFound
		}
		return nil, nil, nil, err
	}

	user.UpdatedAt = requestAt
	user.LastActivatedAt = requestAt

	query = "UPDATE users SET updated_at=?, last_activated_at=? WHERE id=?"
	if _, err := tx.Exec(query, requestAt, requestAt, userID); err != nil {
		return nil, nil, nil, err
	}

	return user, loginBonuses, allPresents, nil
}

// isCompleteTodayLogin ログイン処理が終わっているか
func isCompleteTodayLogin(lastActivatedAt, requestAt time.Time) bool {
	return lastActivatedAt.Year() == requestAt.Year() &&
		lastActivatedAt.Month() == requestAt.Month() &&
		lastActivatedAt.Day() == requestAt.Day()
}

// obtainLoginBonus
func (h *Handler) obtainLoginBonus(tx *sqlx.Tx, userID int64, requestAt int64) ([]*UserLoginBonus, error) {
	// login bonus masterから有効なログインボーナスを取得
	loginBonuses := make([]*LoginBonusMaster, 0)
	// TODO: index
	query := "SELECT * FROM login_bonus_masters WHERE start_at <= ? AND end_at >= ?"
	if err := tx.Select(&loginBonuses, query, requestAt, requestAt); err != nil {
		return nil, err
	}
	bonusIDs := make([]int64, len(loginBonuses))
	for i := range loginBonuses {
		bonusIDs[i] = loginBonuses[i].ID
	}

	userBonuses := make([]*UserLoginBonus, 0, len(loginBonuses))
	query, args, err := sqlx.In("SELECT * FROM user_login_bonuses WHERE user_id=? AND login_bonus_id IN (?)", userID, bonusIDs)
	if err != nil {
		return nil, err
	}
	if err := tx.Select(&userBonuses, query, args...); err != nil {
		return nil, err
	}
	userBonusesMap := make(map[int64]*UserLoginBonus, len(userBonuses))
	for i := range userBonuses {
		userBonusesMap[userBonuses[i].LoginBonusID] = userBonuses[i]
	}

	sendLoginBonuses := make([]*UserLoginBonus, 0)
	for _, bonus := range loginBonuses {
		initBonus := false

		userBonus, ok := userBonusesMap[bonus.ID]
		if !ok {
			initBonus = true

			ubID, err := h.generateID()
			if err != nil {
				return nil, err
			}
			userBonus = &UserLoginBonus{ // ボーナス初期化
				ID:                 ubID,
				UserID:             userID,
				LoginBonusID:       bonus.ID,
				LastRewardSequence: 0,
				LoopCount:          1,
				CreatedAt:          requestAt,
				UpdatedAt:          requestAt,
			}
		}

		// ボーナス進捗更新
		if userBonus.LastRewardSequence < bonus.ColumnCount {
			userBonus.LastRewardSequence++
		} else {
			if bonus.Looped {
				userBonus.LoopCount += 1
				userBonus.LastRewardSequence = 1
			} else {
				// 上限まで付与完了
				continue
			}
		}
		userBonus.UpdatedAt = requestAt

		// 今回付与するリソース取得
		rewardItem := new(LoginBonusRewardMaster)
		query = "SELECT * FROM login_bonus_reward_masters WHERE login_bonus_id=? AND reward_sequence=?"
		if err := tx.Get(rewardItem, query, bonus.ID, userBonus.LastRewardSequence); err != nil {
			if err == sql.ErrNoRows {
				return nil, ErrLoginBonusRewardNotFound
			}
			return nil, err
		}

		_, _, _, err := h.obtainItem(tx, userID, rewardItem.ItemID, rewardItem.ItemType, rewardItem.Amount, requestAt)
		if err != nil {
			return nil, err
		}

		// 進捗の保存
		if initBonus {
			query = "INSERT INTO user_login_bonuses(id, user_id, login_bonus_id, last_reward_sequence, loop_count, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)"
			if _, err = tx.Exec(query, userBonus.ID, userBonus.UserID, userBonus.LoginBonusID, userBonus.LastRewardSequence, userBonus.LoopCount, userBonus.CreatedAt, userBonus.UpdatedAt); err != nil {
				return nil, err
			}
		} else {
			query = "UPDATE user_login_bonuses SET last_reward_sequence=?, loop_count=?, updated_at=? WHERE id=?"
			if _, err = tx.Exec(query, userBonus.LastRewardSequence, userBonus.LoopCount, userBonus.UpdatedAt, userBonus.ID); err != nil {
				return nil, err
			}
		}

		sendLoginBonuses = append(sendLoginBonuses, userBonus)
	}

	return sendLoginBonuses, nil
}

// obtainPresent プレゼント付与処理
func (h *Handler) obtainPresent(tx *sqlx.Tx, txPresent *sqlx.Tx, userID int64, requestAt int64) ([]*UserPresent, error) {
	normalPresents := make([]*PresentAllMaster, 0)
	query := "SELECT * FROM present_all_masters WHERE registered_start_at <= ? AND registered_end_at >= ?"
	if err := tx.Select(&normalPresents, query, requestAt, requestAt); err != nil {
		return nil, err
	}

	normalPresentsIDs := make([]int64, len(normalPresents))
	for i := range normalPresents {
		normalPresentsIDs[i] = normalPresents[i].ID
	}

	receivedIDs := make([]int64, 0, len(normalPresents))
	query, args, err := sqlx.In("SELECT `present_all_id` FROM user_present_all_received_history WHERE user_id=? AND present_all_id IN (?)", userID, normalPresentsIDs)
	if err != nil {
		return nil, err
	}
	if err := tx.Select(&receivedIDs, query, args...); err != nil && err != sql.ErrNoRows {
		return nil, err
	}
	receivedIDsSet := make(map[int64]struct{}, len(receivedIDs))
	for i := range receivedIDs {
		receivedIDsSet[receivedIDs[i]] = struct{}{}
	}

	// 全員プレゼント取得情報更新
	obtainPresents := make([]*UserPresent, 0)
	ups := make([]UserPresent, 0)
	histories := make([]UserPresentAllReceivedHistory, 0)
	for _, np := range normalPresents {
		if _, ok := receivedIDsSet[np.ID]; ok {
			continue
		}

		// user present boxに入れる
		pID, err := h.generateID()
		if err != nil {
			return nil, err
		}
		up := UserPresent{
			ID:             pID,
			UserID:         userID,
			SentAt:         requestAt,
			ItemType:       np.ItemType,
			ItemID:         np.ItemID,
			Amount:         int(np.Amount),
			PresentMessage: np.PresentMessage,
			CreatedAt:      requestAt,
			UpdatedAt:      requestAt,
		}
		ups = append(ups, up)

		history := &UserPresentAllReceivedHistory{
			UserID:       userID,
			PresentAllID: np.ID,
			ReceivedAt:   requestAt,
			CreatedAt:    requestAt,
			UpdatedAt:    requestAt,
		}
		histories = append(histories, *history)

		obtainPresents = append(obtainPresents, &up)
	}

	if len(ups) != 0 {
		queryUp := "INSERT INTO user_presents(id, user_id, sent_at, item_type, item_id, amount, present_message, created_at, updated_at) VALUES (:id, :user_id, :sent_at, :item_type, :item_id, :amount, :present_message, :created_at, :updated_at)"
		_, err = txPresent.NamedExec(queryUp, ups)
		if err != nil {
			return nil, err
		}

		queryHistory := "INSERT INTO user_present_all_received_history(user_id, present_all_id, received_at, created_at, updated_at) VALUES (:user_id, :present_all_id, :received_at, :created_at, :updated_at)"
		_, err = tx.NamedExec(queryHistory, histories)
		if err != nil {
			return nil, err
		}
	}

	return obtainPresents, nil
}

// obtainItem アイテム付与処理
func (h *Handler) obtainItem(tx *sqlx.Tx, userID, itemID int64, itemType int, obtainAmount int64, requestAt int64) ([]int64, []*UserCard, []*UserItem, error) {
	obtainCoins := make([]int64, 0)
	obtainCards := make([]*UserCard, 0)
	obtainItems := make([]*UserItem, 0)

	switch itemType {
	case 1: // coin
		user := new(User)
		query := "SELECT * FROM users WHERE id=?"
		if err := tx.Get(user, query, userID); err != nil {
			if err == sql.ErrNoRows {
				return nil, nil, nil, ErrUserNotFound
			}
			return nil, nil, nil, err
		}

		query = "UPDATE users SET isu_coin=? WHERE id=?"
		totalCoin := user.IsuCoin + obtainAmount
		if _, err := tx.Exec(query, totalCoin, user.ID); err != nil {
			return nil, nil, nil, err
		}
		obtainCoins = append(obtainCoins, obtainAmount)

	case 2: // card(ハンマー)
		query := "SELECT * FROM item_masters WHERE id=? AND item_type=?"
		item := new(ItemMaster)
		if err := tx.Get(item, query, itemID, itemType); err != nil {
			if err == sql.ErrNoRows {
				return nil, nil, nil, ErrItemNotFound
			}
			return nil, nil, nil, err
		}

		cID, err := h.generateID()
		if err != nil {
			return nil, nil, nil, err
		}
		card := &UserCard{
			ID:           cID,
			UserID:       userID,
			CardID:       item.ID,
			AmountPerSec: *item.AmountPerSec,
			Level:        1,
			TotalExp:     0,
			CreatedAt:    requestAt,
			UpdatedAt:    requestAt,
		}
		query = "INSERT INTO user_cards(id, user_id, card_id, amount_per_sec, level, total_exp, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
		if _, err := tx.Exec(query, card.ID, card.UserID, card.CardID, card.AmountPerSec, card.Level, card.TotalExp, card.CreatedAt, card.UpdatedAt); err != nil {
			return nil, nil, nil, err
		}
		obtainCards = append(obtainCards, card)

	case 3, 4: // 強化素材
		query := "SELECT * FROM item_masters WHERE id=? AND item_type=?"
		item := new(ItemMaster)
		if err := tx.Get(item, query, itemID, itemType); err != nil {
			if err == sql.ErrNoRows {
				return nil, nil, nil, ErrItemNotFound
			}
			return nil, nil, nil, err
		}
		// 所持数取得
		query = "SELECT * FROM user_items WHERE user_id=? AND item_id=?"
		uitem := new(UserItem)
		if err := tx.Get(uitem, query, userID, item.ID); err != nil {
			if err != sql.ErrNoRows {
				return nil, nil, nil, err
			}
			uitem = nil
		}

		if uitem == nil { // 新規作成
			uitemID, err := h.generateID()
			if err != nil {
				return nil, nil, nil, err
			}
			uitem = &UserItem{
				ID:        uitemID,
				UserID:    userID,
				ItemType:  item.ItemType,
				ItemID:    item.ID,
				Amount:    int(obtainAmount),
				CreatedAt: requestAt,
				UpdatedAt: requestAt,
			}
			query = "INSERT INTO user_items(id, user_id, item_id, item_type, amount, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)"
			if _, err := tx.Exec(query, uitem.ID, userID, uitem.ItemID, uitem.ItemType, uitem.Amount, requestAt, requestAt); err != nil {
				return nil, nil, nil, err
			}

		} else { // 更新
			uitem.Amount += int(obtainAmount)
			uitem.UpdatedAt = requestAt
			query = "UPDATE user_items SET amount=?, updated_at=? WHERE id=?"
			if _, err := tx.Exec(query, uitem.Amount, uitem.UpdatedAt, uitem.ID); err != nil {
				return nil, nil, nil, err
			}
		}

		obtainItems = append(obtainItems, uitem)

	default:
		return nil, nil, nil, ErrInvalidItemType
	}

	return obtainCoins, obtainCards, obtainItems, nil
}

type UpdateIcuCoin struct {
	ID      int64 `json:"id" db:"id"`
	IsuCoin int64 `json:"isu_coin" db:"isu_coin"`
}

func (h *Handler) obtainItem1(tx *sqlx.Tx, userID, itemID int64, itemType int, obtainAmount int64, requestAt int64) (User, int64, error) {
	// coin
	user := new(User)
	query := "SELECT * FROM users WHERE id=?"
	if err := tx.Get(user, query, userID); err != nil {
		if err == sql.ErrNoRows {
			return User{}, 0, ErrUserNotFound
		}
		return User{}, 0, err
	}

	totalCoin := user.IsuCoin + obtainAmount

	return User{ID: user.ID, IsuCoin: totalCoin}, obtainAmount, nil
}

// obtainItem アイテム付与処理
func (h *Handler) obtainItem2(tx *sqlx.Tx, userID, itemID int64, itemType int, obtainAmount int64, requestAt int64, item *ItemMaster) (UserCard, error) {
	// card(ハンマー)
	cID, err := h.generateID()
	if err != nil {
		return UserCard{}, err
	}
	card := UserCard{
		ID:           cID,
		UserID:       userID,
		CardID:       item.ID,
		AmountPerSec: *item.AmountPerSec,
		Level:        1,
		TotalExp:     0,
		CreatedAt:    requestAt,
		UpdatedAt:    requestAt,
	}

	return card, nil
}

// obtainItem アイテム付与処理
func (h *Handler) obtainItem3And4(tx *sqlx.Tx, userID, itemID int64, itemType int, obtainAmount int64, requestAt int64, item *ItemMaster, uitem *UserItem) (UserItem, error) {
	obtainItems := make([]*UserItem, 0)
	// 強化素材

	if uitem == nil { // 新規作成
		uitemID, err := h.generateID()
		if err != nil {
			return UserItem{}, err
		}
		uitem = &UserItem{
			ID:        uitemID,
			UserID:    userID,
			ItemType:  item.ItemType,
			ItemID:    item.ID,
			Amount:    int(obtainAmount),
			CreatedAt: requestAt,
			UpdatedAt: requestAt,
		}
	} else { // 更新
		uitem.Amount += int(obtainAmount)
		uitem.UpdatedAt = requestAt
	}

	obtainItems = append(obtainItems, uitem)

	return *uitem, nil
}

func runDBInit(hostNum string) ([]byte, error) {
	host := os.Getenv("ISUCON_DB_HOST" + hostNum)

	cmd := exec.Command("/bin/sh", "-c", SQLDirectory+"init.sh")
	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env, "ISUCON_DB_HOST="+host)
	return cmd.CombinedOutput()
}

// initialize 初期化処理
// POST /initialize
func initialize(c echo.Context) error {
	dbx1, err := connectDB(true, "1")
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}
	defer dbx1.Close()
	dbx2, err := connectDB(true, "2")
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}
	defer dbx2.Close()

	errg := errgroup.Group{}
	errg.Go(func() error {
		if out, err := runDBInit("1"); err != nil {
			c.Logger().Errorf("Failed to initialize %s: %v", string(out), err)
			return err
		}
		return nil
	})
	errg.Go(func() error {
		if out, err := runDBInit("2"); err != nil {
			c.Logger().Errorf("Failed to initialize %s: %v", string(out), err)
			return err
		}
		return nil
	})
	err = errg.Wait()
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}

	go func() {
		if _, err := http.Get("http://localhost:9000/api/group/collect"); err != nil {
			c.Logger().Printf("failed to communicate with pprotein: %v", err)
		}
	}()

	// initialize cache
	{
		// マスタ確認
		query := "SELECT * FROM version_masters WHERE status=1"
		if err := dbx1.Get(masterVersion, query); err != nil {
			if err == sql.ErrNoRows {
				return errorResponse(c, http.StatusNotFound, fmt.Errorf("active master version is not found"))
			}
			return errorResponse(c, http.StatusInternalServerError, err)
		}

		// userSession
		var sessions []Session
		query = "SELECT * FROM user_sessions WHERE deleted_at IS NULL"
		if err := dbx1.Select(&sessions, query); err != nil {
			return errorResponse(c, http.StatusInternalServerError, err)
		}
		userSessions.Clear()
		for i := range sessions {
			userSessions.Set(sessions[i].SessionID, sessions[i])
		}

		var userDevices []UserDevice
		query = "SELECT * FROM user_devices"
		if err := dbx1.Select(&userDevices, query); err != nil {
		}
		userDevicesSet.Clear()
		for i := range userDevices {
			userDevicesSet.Set(getUserDevicesKey(userDevices[i].UserID, userDevices[i].PlatformID), struct{}{})
		}
	}

	return successResponse(c, &InitializeResponse{
		Language: "go",
	})
}

type InitializeResponse struct {
	Language string `json:"language"`
}

// createUser ユーザの作成
// POST /user
func (h *Handler) createUser(c echo.Context) error {
	// parse body
	defer c.Request().Body.Close()
	req := new(CreateUserRequest)
	if err := parseRequestBody(c, req); err != nil {
		return errorResponse(c, http.StatusBadRequest, err)
	}

	if req.ViewerID == "" || req.PlatformType < 1 || req.PlatformType > 3 {
		return errorResponse(c, http.StatusBadRequest, ErrInvalidRequestBody)
	}

	requestAt, err := getRequestTime(c)
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, ErrGetRequestTime)
	}

	tx, err := h.DB.Beginx()
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}
	defer tx.Rollback() //nolint:errcheck

	// ユーザ作成
	uID, err := h.generateID()
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}
	user := &User{
		ID:              uID,
		IsuCoin:         0,
		LastGetRewardAt: requestAt,
		LastActivatedAt: requestAt,
		RegisteredAt:    requestAt,
		CreatedAt:       requestAt,
		UpdatedAt:       requestAt,
	}
	query := "INSERT INTO users(id, last_activated_at, registered_at, last_getreward_at, created_at, updated_at) VALUES(?, ?, ?, ?, ?, ?)"
	if _, err = tx.Exec(query, user.ID, user.LastActivatedAt, user.RegisteredAt, user.LastGetRewardAt, user.CreatedAt, user.UpdatedAt); err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}

	udID, err := h.generateID()
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}
	userDevice := &UserDevice{
		ID:           udID,
		UserID:       user.ID,
		PlatformID:   req.ViewerID,
		PlatformType: req.PlatformType,
		CreatedAt:    requestAt,
		UpdatedAt:    requestAt,
	}
	query = "INSERT INTO user_devices(id, user_id, platform_id, platform_type, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)"
	_, err = tx.Exec(query, userDevice.ID, user.ID, req.ViewerID, req.PlatformType, requestAt, requestAt)
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}

	// 初期デッキ付与
	initCard := new(ItemMaster)
	query = "SELECT * FROM item_masters WHERE id=?"
	if err = tx.Get(initCard, query, 2); err != nil {
		if err == sql.ErrNoRows {
			return errorResponse(c, http.StatusNotFound, ErrItemNotFound)
		}
		return errorResponse(c, http.StatusInternalServerError, err)
	}

	initCards := make([]*UserCard, 0, 3)
	for i := 0; i < 3; i++ {
		cID, err := h.generateID()
		if err != nil {
			return errorResponse(c, http.StatusInternalServerError, err)
		}
		card := &UserCard{
			ID:           cID,
			UserID:       user.ID,
			CardID:       initCard.ID,
			AmountPerSec: *initCard.AmountPerSec,
			Level:        1,
			TotalExp:     0,
			CreatedAt:    requestAt,
			UpdatedAt:    requestAt,
		}
		// TODO: bulk(3回しかたたかれてない)
		query = "INSERT INTO user_cards(id, user_id, card_id, amount_per_sec, level, total_exp, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
		if _, err := tx.Exec(query, card.ID, card.UserID, card.CardID, card.AmountPerSec, card.Level, card.TotalExp, card.CreatedAt, card.UpdatedAt); err != nil {
			return errorResponse(c, http.StatusInternalServerError, err)
		}
		initCards = append(initCards, card)
	}

	deckID, err := h.generateID()
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}
	initDeck := &UserDeck{
		ID:        deckID,
		UserID:    user.ID,
		CardID1:   initCards[0].ID,
		CardID2:   initCards[1].ID,
		CardID3:   initCards[2].ID,
		CreatedAt: requestAt,
		UpdatedAt: requestAt,
	}
	query = "INSERT INTO user_decks(id, user_id, user_card_id_1, user_card_id_2, user_card_id_3, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)"
	if _, err := tx.Exec(query, initDeck.ID, initDeck.UserID, initDeck.CardID1, initDeck.CardID2, initDeck.CardID3, initDeck.CreatedAt, initDeck.UpdatedAt); err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}

	txPresent, err := h.PresentDB.Beginx()
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}
	defer txPresent.Rollback() //nolint:errcheck

	// ログイン処理
	user, loginBonuses, presents, err := h.loginProcess(tx, txPresent, user.ID, requestAt)
	if err != nil {
		if err == ErrUserNotFound || err == ErrItemNotFound || err == ErrLoginBonusRewardNotFound {
			return errorResponse(c, http.StatusNotFound, err)
		}
		if err == ErrInvalidItemType {
			return errorResponse(c, http.StatusBadRequest, err)
		}
		return errorResponse(c, http.StatusInternalServerError, err)
	}

	// generate session
	sID, err := h.generateID()
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}
	sessID, err := generateUUID()
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}
	sess := &Session{
		ID:        sID,
		UserID:    user.ID,
		SessionID: sessID,
		CreatedAt: requestAt,
		UpdatedAt: requestAt,
		ExpiredAt: requestAt + 86400,
	}
	userSessions.Set(sessID, *sess)
	// async insert
	go func() {
		query = "INSERT INTO user_sessions(id, user_id, session_id, created_at, updated_at, expired_at) VALUES (?, ?, ?, ?, ?, ?)"
		if _, err = tx.Exec(query, sess.ID, sess.UserID, sess.SessionID, sess.CreatedAt, sess.UpdatedAt, sess.ExpiredAt); err != nil {
			c.Logger().Errorf("%w\n", err)
			//return errorResponse(c, http.StatusInternalServerError, err)
		}
	}()

	userDevicesSet.Set(getUserDevicesKey(user.ID, req.ViewerID), struct{}{})
	err = tx.Commit()
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}
	err = txPresent.Commit()
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, err) // 起きたら本当はtxをrollbackする必要あり
	}

	return successResponse(c, &CreateUserResponse{
		UserID:           user.ID,
		ViewerID:         req.ViewerID,
		SessionID:        sess.SessionID,
		CreatedAt:        requestAt,
		UpdatedResources: makeUpdatedResources(requestAt, user, userDevice, initCards, []*UserDeck{initDeck}, nil, loginBonuses, presents),
	})
}

type CreateUserRequest struct {
	ViewerID     string `json:"viewerId"`
	PlatformType int    `json:"platformType"`
}

type CreateUserResponse struct {
	UserID           int64            `json:"userId"`
	ViewerID         string           `json:"viewerId"`
	SessionID        string           `json:"sessionId"`
	CreatedAt        int64            `json:"createdAt"`
	UpdatedResources *UpdatedResource `json:"updatedResources"`
}

// login ログイン
// POST /login
func (h *Handler) login(c echo.Context) error {
	defer c.Request().Body.Close()
	req := new(LoginRequest)
	if err := parseRequestBody(c, req); err != nil {
		return errorResponse(c, http.StatusBadRequest, err)
	}

	requestAt, err := getRequestTime(c)
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, ErrGetRequestTime)
	}

	user := new(User)
	query := "SELECT * FROM users WHERE id=?"
	if err := h.DB.Get(user, query, req.UserID); err != nil {
		if err == sql.ErrNoRows {
			return errorResponse(c, http.StatusNotFound, ErrUserNotFound)
		}
		return errorResponse(c, http.StatusInternalServerError, err)
	}

	// check ban
	isBan, err := h.checkBan(user.ID)
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}
	if isBan {
		return errorResponse(c, http.StatusForbidden, ErrForbidden)
	}

	// viewer id check
	if err = h.checkViewerID(user.ID, req.ViewerID); err != nil {
		if err == ErrUserDeviceNotFound {
			return errorResponse(c, http.StatusNotFound, err)
		}
		return errorResponse(c, http.StatusInternalServerError, err)
	}

	tx, err := h.DB.Beginx()
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}
	defer tx.Rollback() //nolint:errcheck

	// async update
	go func() {
		// 以前のsessionを破棄(cacheは最後の値で更新すれば良い)
		query = "UPDATE user_sessions SET deleted_at=? WHERE user_id=? AND deleted_at IS NULL"
		if _, err = tx.Exec(query, requestAt, req.UserID); err != nil {
			c.Logger().Errorf("%w\n", err)
			//return errorResponse(c, http.StatusInternalServerError, err)
		}
	}()
	sID, err := h.generateID()
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}
	sessID, err := generateUUID()
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}
	sess := &Session{
		ID:        sID,
		UserID:    req.UserID,
		SessionID: sessID,
		CreatedAt: requestAt,
		UpdatedAt: requestAt,
		ExpiredAt: requestAt + 86400,
	}
	userSessions.Set(sessID, *sess)
	// async insert
	go func() {
		query = "INSERT INTO user_sessions(id, user_id, session_id, created_at, updated_at, expired_at) VALUES (?, ?, ?, ?, ?, ?)"
		if _, err = tx.Exec(query, sess.ID, sess.UserID, sess.SessionID, sess.CreatedAt, sess.UpdatedAt, sess.ExpiredAt); err != nil {
			c.Logger().Errorf("%w\n", err)
			//return errorResponse(c, http.StatusInternalServerError, err)
		}
	}()

	// すでにログインしているユーザはログイン処理をしない
	if isCompleteTodayLogin(time.Unix(user.LastActivatedAt, 0), time.Unix(requestAt, 0)) {
		user.UpdatedAt = requestAt
		user.LastActivatedAt = requestAt

		query = "UPDATE users SET updated_at=?, last_activated_at=? WHERE id=?"
		if _, err := tx.Exec(query, requestAt, requestAt, req.UserID); err != nil {
			return errorResponse(c, http.StatusInternalServerError, err)
		}

		err = tx.Commit()
		if err != nil {
			return errorResponse(c, http.StatusInternalServerError, err)
		}

		return successResponse(c, &LoginResponse{
			ViewerID:         req.ViewerID,
			SessionID:        sess.SessionID,
			UpdatedResources: makeUpdatedResources(requestAt, user, nil, nil, nil, nil, nil, nil),
		})
	}

	txPresent, err := h.PresentDB.Beginx()
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}
	defer txPresent.Rollback() //nolint:errcheck

	// login process
	user, loginBonuses, presents, err := h.loginProcess(tx, txPresent, req.UserID, requestAt)
	if err != nil {
		if err == ErrUserNotFound || err == ErrItemNotFound || err == ErrLoginBonusRewardNotFound {
			return errorResponse(c, http.StatusNotFound, err)
		}
		if err == ErrInvalidItemType {
			return errorResponse(c, http.StatusBadRequest, err)
		}
		return errorResponse(c, http.StatusInternalServerError, err)
	}

	err = tx.Commit()
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}
	err = txPresent.Commit()
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, err) // 起きたら本当はtxをrollbackする必要あり
	}

	return successResponse(c, &LoginResponse{
		ViewerID:         req.ViewerID,
		SessionID:        sess.SessionID,
		UpdatedResources: makeUpdatedResources(requestAt, user, nil, nil, nil, nil, loginBonuses, presents),
	})
}

type LoginRequest struct {
	ViewerID string `json:"viewerId"`
	UserID   int64  `json:"userId"`
}

type LoginResponse struct {
	ViewerID         string           `json:"viewerId"`
	SessionID        string           `json:"sessionId"`
	UpdatedResources *UpdatedResource `json:"updatedResources"`
}

// listGacha ガチャ一覧
// GET /user/{userID}/gacha/index
func (h *Handler) listGacha(c echo.Context) error {
	userID, err := getUserID(c)
	if err != nil {
		return errorResponse(c, http.StatusBadRequest, err)
	}

	requestAt, err := getRequestTime(c)
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, ErrGetRequestTime)
	}

	gachaMasterList := []*GachaMaster{}
	query := "SELECT * FROM gacha_masters WHERE start_at <= ? AND end_at >= ? ORDER BY display_order ASC"
	err = h.DB.Select(&gachaMasterList, query, requestAt, requestAt)
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}

	if len(gachaMasterList) == 0 {
		return successResponse(c, &ListGachaResponse{
			Gachas: []*GachaData{},
		})
	}

	// ガチャ排出アイテム取得
	gachaDataList := make([]*GachaData, 0)
	query = "SELECT * FROM gacha_item_masters WHERE gacha_id=? ORDER BY id ASC"
	for _, v := range gachaMasterList {
		var gachaItem []*GachaItemMaster
		err = h.DB.Select(&gachaItem, query, v.ID)
		if err != nil {
			return errorResponse(c, http.StatusInternalServerError, err)
		}

		if len(gachaItem) == 0 {
			return errorResponse(c, http.StatusNotFound, fmt.Errorf("not found gacha item"))
		}

		gachaDataList = append(gachaDataList, &GachaData{
			Gacha:     v,
			GachaItem: gachaItem,
		})
	}

	// genearte one time token
	query = "UPDATE user_one_time_tokens SET deleted_at=? WHERE user_id=? AND deleted_at IS NULL"
	if _, err = h.DB.Exec(query, requestAt, userID); err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}
	tID, err := h.generateID()
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}
	tk, err := generateUUID()
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}
	token := &UserOneTimeToken{
		ID:        tID,
		UserID:    userID,
		Token:     tk,
		TokenType: 1,
		CreatedAt: requestAt,
		UpdatedAt: requestAt,
		ExpiredAt: requestAt + 600,
	}
	query = "INSERT INTO user_one_time_tokens(id, user_id, token, token_type, created_at, updated_at, expired_at) VALUES (?, ?, ?, ?, ?, ?, ?)"
	if _, err = h.DB.Exec(query, token.ID, token.UserID, token.Token, token.TokenType, token.CreatedAt, token.UpdatedAt, token.ExpiredAt); err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}

	return successResponse(c, &ListGachaResponse{
		OneTimeToken: token.Token,
		Gachas:       gachaDataList,
	})
}

type ListGachaResponse struct {
	OneTimeToken string       `json:"oneTimeToken"`
	Gachas       []*GachaData `json:"gachas"`
}

type GachaData struct {
	Gacha     *GachaMaster       `json:"gacha"`
	GachaItem []*GachaItemMaster `json:"gachaItemList"`
}

// drawGacha ガチャを引く
// POST /user/{userID}/gacha/draw/{gachaID}/{n}
func (h *Handler) drawGacha(c echo.Context) error {
	userID, err := getUserID(c)
	if err != nil {
		return errorResponse(c, http.StatusBadRequest, err)
	}

	gachaID := c.Param("gachaID")
	if gachaID == "" {
		return errorResponse(c, http.StatusBadRequest, fmt.Errorf("invalid gachaID"))
	}

	gachaCount, err := strconv.ParseInt(c.Param("n"), 10, 64)
	if err != nil {
		return errorResponse(c, http.StatusBadRequest, err)
	}
	if gachaCount != 1 && gachaCount != 10 {
		return errorResponse(c, http.StatusBadRequest, fmt.Errorf("invalid draw gacha times"))
	}

	defer c.Request().Body.Close()
	req := new(DrawGachaRequest)
	if err = parseRequestBody(c, req); err != nil {
		return errorResponse(c, http.StatusBadRequest, err)
	}

	requestAt, err := getRequestTime(c)
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, ErrGetRequestTime)
	}

	if err = h.checkOneTimeToken(req.OneTimeToken, 1, requestAt); err != nil {
		if err == ErrInvalidToken {
			return errorResponse(c, http.StatusBadRequest, err)
		}
		return errorResponse(c, http.StatusInternalServerError, err)
	}

	if err = h.checkViewerID(userID, req.ViewerID); err != nil {
		if err == ErrUserDeviceNotFound {
			return errorResponse(c, http.StatusNotFound, err)
		}
		return errorResponse(c, http.StatusInternalServerError, err)
	}

	consumedCoin := int64(gachaCount * 1000)

	// userのisuconが足りるか
	user := new(User)
	query := "SELECT * FROM users WHERE id=?"
	if err := h.DB.Get(user, query, userID); err != nil {
		if err == sql.ErrNoRows {
			return errorResponse(c, http.StatusNotFound, ErrUserNotFound)
		}
		return errorResponse(c, http.StatusInternalServerError, err)
	}
	if user.IsuCoin < consumedCoin {
		return errorResponse(c, http.StatusConflict, fmt.Errorf("not enough isucon"))
	}

	// gachaIDからガチャマスタの取得
	query = "SELECT * FROM gacha_masters WHERE id=? AND start_at <= ? AND end_at >= ?"
	gachaInfo := new(GachaMaster)
	if err = h.DB.Get(gachaInfo, query, gachaID, requestAt, requestAt); err != nil {
		if sql.ErrNoRows == err {
			return errorResponse(c, http.StatusNotFound, fmt.Errorf("not found gacha"))
		}
		return errorResponse(c, http.StatusInternalServerError, err)
	}

	// gachaItemMasterからアイテムリスト取得
	gachaItemList := make([]*GachaItemMaster, 0)
	err = h.DB.Select(&gachaItemList, "SELECT * FROM gacha_item_masters WHERE gacha_id=? ORDER BY id ASC", gachaID)
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}
	if len(gachaItemList) == 0 {
		return errorResponse(c, http.StatusNotFound, fmt.Errorf("not found gacha item"))
	}

	// weightの合計値を算出
	var sum int64
	err = h.DB.Get(&sum, "SELECT SUM(weight) FROM gacha_item_masters WHERE gacha_id=?", gachaID)
	if err != nil {
		if err == sql.ErrNoRows {
			return errorResponse(c, http.StatusNotFound, err)
		}
		return errorResponse(c, http.StatusInternalServerError, err)
	}

	// random値の導出 & 抽選
	result := make([]*GachaItemMaster, 0, gachaCount)
	for i := 0; i < int(gachaCount); i++ {
		random := rand.Int63n(sum)
		boundary := 0
		for _, v := range gachaItemList {
			boundary += v.Weight
			if random < int64(boundary) {
				result = append(result, v)
				break
			}
		}
	}

	// 直付与 => プレゼントに入れる
	presents := make([]*UserPresent, 0, gachaCount)
	for _, v := range result {
		pID, err := h.generateID()
		if err != nil {
			return errorResponse(c, http.StatusInternalServerError, err)
		}
		present := &UserPresent{
			ID:             pID,
			UserID:         userID,
			SentAt:         requestAt,
			ItemType:       v.ItemType,
			ItemID:         v.ItemID,
			Amount:         v.Amount,
			PresentMessage: fmt.Sprintf("%sの付与アイテムです", gachaInfo.Name),
			CreatedAt:      requestAt,
			UpdatedAt:      requestAt,
		}

		presents = append(presents, present)
	}

	if len(presents) == 0 {
		return successResponse(c, &DrawGachaResponse{
			Presents: presents,
		})
	}

	tx, err := h.DB.Beginx()
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}
	defer tx.Rollback() //nolint:errcheck

	tx2, err := h.PresentDB.Beginx()
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}
	defer tx2.Rollback() //nolint:errcheck

	queryPresents := "INSERT INTO user_presents(id, user_id, sent_at, item_type, item_id, amount, present_message, created_at, updated_at) VALUES (:id, :user_id, :sent_at, :item_type, :item_id, :amount, :present_message, :created_at, :updated_at)"
	_, err = tx2.NamedExec(queryPresents, presents)
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}

	// isuconをへらす
	query = "UPDATE users SET isu_coin=? WHERE id=?"
	totalCoin := user.IsuCoin - consumedCoin
	if _, err := tx.Exec(query, totalCoin, user.ID); err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}

	err = tx.Commit()
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}
	err = tx2.Commit()
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, err) // 起きたら本当はtxをrollbackする必要あり
	}

	return successResponse(c, &DrawGachaResponse{
		Presents: presents,
	})
}

type DrawGachaRequest struct {
	ViewerID     string `json:"viewerId"`
	OneTimeToken string `json:"oneTimeToken"`
}

type DrawGachaResponse struct {
	Presents []*UserPresent `json:"presents"`
}

// listPresent プレゼント一覧
// GET /user/{userID}/present/index/{n}
func (h *Handler) listPresent(c echo.Context) error {
	n, err := strconv.Atoi(c.Param("n"))
	if err != nil {
		return errorResponse(c, http.StatusBadRequest, fmt.Errorf("invalid index number (n) parameter"))
	}
	if n == 0 {
		return errorResponse(c, http.StatusBadRequest, fmt.Errorf("index number (n) should be more than or equal to 1"))
	}

	userID, err := getUserID(c)
	if err != nil {
		return errorResponse(c, http.StatusBadRequest, fmt.Errorf("invalid userID parameter"))
	}

	offset := PresentCountPerPage * (n - 1)
	var presentList []*UserPresent
	query := `
	SELECT * FROM user_presents
	WHERE user_id = ? AND deleted_at IS NULL
	ORDER BY created_at DESC, id
	LIMIT ? OFFSET ?`
	if err = h.PresentDB.Select(&presentList, query, userID, PresentCountPerPage+1, offset); err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}

	isNext := false
	if len(presentList) > PresentCountPerPage {
		isNext = true
		presentList = presentList[:PresentCountPerPage]
	}

	return successResponse(c, &ListPresentResponse{
		Presents: presentList,
		IsNext:   isNext,
	})
}

type ListPresentResponse struct {
	Presents []*UserPresent `json:"presents"`
	IsNext   bool           `json:"isNext"`
}

// receivePresent プレゼント受け取り
// POST /user/{userID}/present/receive
func (h *Handler) receivePresent(c echo.Context) error {
	// read body
	defer c.Request().Body.Close()
	req := new(ReceivePresentRequest)
	if err := parseRequestBody(c, req); err != nil {
		return errorResponse(c, http.StatusBadRequest, err)
	}

	userID, err := getUserID(c)
	if err != nil {
		return errorResponse(c, http.StatusBadRequest, err)
	}

	requestAt, err := getRequestTime(c)
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, ErrGetRequestTime)
	}

	if len(req.PresentIDs) == 0 {
		return errorResponse(c, http.StatusUnprocessableEntity, fmt.Errorf("presentIds is empty"))
	}

	if err = h.checkViewerID(userID, req.ViewerID); err != nil {
		if err == ErrUserDeviceNotFound {
			return errorResponse(c, http.StatusNotFound, err)
		}
		return errorResponse(c, http.StatusInternalServerError, err)
	}

	tx2, err := h.PresentDB.Beginx()
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}
	defer tx2.Rollback() //nolint:errcheck

	// user_presentsに入っているが未取得のプレゼント取得
	query := "SELECT * FROM user_presents WHERE id IN (?) AND deleted_at IS NULL FOR UPDATE"
	query, params, err := sqlx.In(query, req.PresentIDs)
	if err != nil {
		return errorResponse(c, http.StatusBadRequest, err)
	}
	obtainPresent := []*UserPresent{}
	if err = tx2.Select(&obtainPresent, query, params...); err != nil {
		return errorResponse(c, http.StatusBadRequest, err)
	}

	if len(obtainPresent) == 0 {
		err := tx2.Commit()
		if err != nil {
			return errorResponse(c, http.StatusInternalServerError, err)
		}

		return successResponse(c, &ReceivePresentResponse{
			UpdatedResources: makeUpdatedResources(requestAt, nil, nil, nil, nil, nil, nil, []*UserPresent{}),
		})
	}

	obtainPresentIDs := make([]int64, len(obtainPresent))
	for i := range obtainPresent {
		if obtainPresent[i].DeletedAt != nil {
			return errorResponse(c, http.StatusInternalServerError, fmt.Errorf("received present"))
		}
		obtainPresentIDs[i] = obtainPresent[i].ID
	}

	query, args, err := sqlx.In("UPDATE user_presents SET deleted_at=?, updated_at=? WHERE id IN (?)", requestAt, requestAt, obtainPresentIDs)
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}
	if _, err := tx2.Exec(query, args...); err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}

	itemIDs := []int64{}
	for i := range obtainPresent {
		if obtainPresent[i].ItemType == 2 || obtainPresent[i].ItemType == 3 || obtainPresent[i].ItemType == 4 {
			itemIDs = append(itemIDs, obtainPresent[i].ItemID)
		}
	}

	tx1, err := h.DB.Beginx()
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}
	defer tx1.Rollback() //nolint:errcheck

	// カード所持情報のバリデーション

	itemMasters := make([]*ItemMaster, 0)
	if len(itemIDs) != 0 {
		query = "SELECT * FROM item_masters WHERE id IN (?)"
		query, params, err = sqlx.In(query, itemIDs)
		if err != nil {
			return errorResponse(c, http.StatusInternalServerError, err)
		}
		if err = tx1.Select(&itemMasters, query, params...); err != nil {
			return errorResponse(c, http.StatusInternalServerError, err)
		}
	}

	userIDs := []int64{}
	for i := range obtainPresent {
		if obtainPresent[i].ItemType == 1 {
			userIDs = append(userIDs, obtainPresent[i].UserID)
		}
	}
	usersExists := make([]*User, 0)
	if len(userIDs) != 0 {
		query = "SELECT * FROM users WHERE id IN (?)"
		query, params, err = sqlx.In(query, userIDs)
		if err != nil {
			return errorResponse(c, http.StatusInternalServerError, err)
		}
		if err = tx1.Select(&usersExists, query, params...); err != nil {
			return errorResponse(c, http.StatusInternalServerError, err)
		}
	}

	type Temp struct {
		UserID int64
		ItemID int64
	}
	temps := []Temp{}
	for i := range obtainPresent {
		if obtainPresent[i].ItemType == 3 || obtainPresent[i].ItemType == 4 {
			temps = append(temps, Temp{UserID: obtainPresent[i].UserID, ItemID: obtainPresent[i].ItemID})
		}
	}
	usersItems := make([]*UserItem, 0)
	if len(temps) != 0 {
		queryTemp := "SELECT * FROM user_items WHERE (user_id, item_id) IN ("
		for i := range temps {
			queryTemp += "(" + strconv.Itoa(int(temps[i].UserID)) + ", " + strconv.Itoa(int(temps[i].ItemID)) + ")"
			if len(temps)-1 != i {
				queryTemp += ","
			}
		}
		queryTemp += ")"
		err = tx1.Select(&usersItems, queryTemp)
		if err != nil {
			return errorResponse(c, http.StatusInternalServerError, err)
		}
	}

	// 配布処理
	cards := []UserCard{}
	items := []UserItem{}
	updateIsuCoins := []User{}
	for i := range obtainPresent {
		obtainPresent[i].UpdatedAt = requestAt
		obtainPresent[i].DeletedAt = &requestAt
		v := obtainPresent[i]

		// TODO: 5N+1くらいになってる
		switch v.ItemType {
		case 1: // coin
			exist := false
			userE := &User{}
			for j := range usersExists {
				if usersExists[j].ID == v.UserID {
					exist = true
					userE = usersExists[j]
				}
			}
			if exist {
				// updateIsuCoin, _, err = h.obtainItem1(tx1, v.UserID, v.ItemID, v.ItemType, int64(v.Amount), requestAt)
				updateIsuCoins = append(updateIsuCoins, User{ID: v.UserID, IsuCoin: userE.IsuCoin + int64(v.Amount)})
			} else {
				err = ErrUserNotFound
			}
		case 2: // card(ハンマー)
			var itemMaster *ItemMaster
			exist := false
			for j := range itemMasters {
				if itemMasters[j].ID == v.ItemID && itemMasters[j].ItemType == v.ItemType {
					itemMaster = itemMasters[j]
					exist = true
				}
			}
			if exist {
				var tmpCard UserCard
				tmpCard, err = h.obtainItem2(tx1, v.UserID, v.ItemID, v.ItemType, int64(v.Amount), requestAt, itemMaster)
				cards = append(cards, tmpCard)
			} else {
				err = ErrItemNotFound
			}
		case 3, 4: // 強化素材
			var itemMaster *ItemMaster
			var usersItem *UserItem
			exist := false
			for j := range itemMasters {
				if itemMasters[j].ID == v.ItemID && itemMasters[j].ItemType == v.ItemType {
					itemMaster = itemMasters[j]
					exist = true
				}
			}
			for j := range usersItems {
				if usersItems[j].ItemID == v.ItemID && usersItems[j].UserID == v.UserID {
					usersItem = usersItems[j]
				}
			}
			if exist {
				var tmpItem UserItem
				tmpItem, err = h.obtainItem3And4(tx1, v.UserID, v.ItemID, v.ItemType, int64(v.Amount), requestAt, itemMaster, usersItem)
				items = append(items, tmpItem)
			} else {
				err = ErrItemNotFound
			}
		}
		if err != nil {
			if err == ErrUserNotFound || err == ErrItemNotFound {
				return errorResponse(c, http.StatusNotFound, err)
			}
			if err == ErrInvalidItemType {
				return errorResponse(c, http.StatusBadRequest, err)
			}
			return errorResponse(c, http.StatusInternalServerError, err)
		}
	}

	if len(cards) != 0 {
		queryCards := "INSERT INTO user_cards(id, user_id, card_id, amount_per_sec, level, total_exp, created_at, updated_at) VALUES (:id, :user_id, :card_id, :amount_per_sec, :level, :total_exp, :created_at, :updated_at)"
		_, err = tx1.NamedExec(queryCards, cards)
		if err != nil {
			return errorResponse(c, http.StatusInternalServerError, err)
		}
	}

	if len(items) != 0 {
		queryItems := "INSERT INTO user_items(id, user_id, item_id, item_type, amount, created_at, updated_at) VALUES (:id, :user_id, :item_id, :item_type, :amount, :created_at, :updated_at) ON DUPLICATE KEY UPDATE amount = VALUES(amount), updated_at = VALUES(updated_at);"
		_, err = tx1.NamedExec(queryItems, items)
		if err != nil {
			return errorResponse(c, http.StatusInternalServerError, err)
		}
	}

	if len(updateIsuCoins) != 0 {
		queryCoins := "INSERT INTO users(id, isu_coin, last_activated_at, registered_at, last_getreward_at, created_at, updated_at) VALUES (:id, :isu_coin, :last_activated_at, :registered_at, :last_getreward_at, :created_at, :updated_at) ON DUPLICATE KEY UPDATE isu_coin = VALUES(isu_coin)"
		_, err = tx1.NamedExec(queryCoins, updateIsuCoins)
		if err != nil {
			return errorResponse(c, http.StatusInternalServerError, err)
		}
	}

	err = tx1.Commit()
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}
	err = tx2.Commit()
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, err) // 起きたら本当はtxをrollbackする必要あり
	}

	return successResponse(c, &ReceivePresentResponse{
		UpdatedResources: makeUpdatedResources(requestAt, nil, nil, nil, nil, nil, nil, obtainPresent),
	})
}

type ReceivePresentRequest struct {
	ViewerID   string  `json:"viewerId"`
	PresentIDs []int64 `json:"presentIds"`
}

type ReceivePresentResponse struct {
	UpdatedResources *UpdatedResource `json:"updatedResources"`
}

// listItem アイテムリスト
// GET /user/{userID}/item
func (h *Handler) listItem(c echo.Context) error {
	userID, err := getUserID(c)
	if err != nil {
		return errorResponse(c, http.StatusBadRequest, err)
	}

	requestAt, err := getRequestTime(c)
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, ErrGetRequestTime)
	}

	user := new(User)
	query := "SELECT * FROM users WHERE id=?"
	if err = h.DB.Get(user, query, userID); err != nil {
		if err == sql.ErrNoRows {
			return errorResponse(c, http.StatusNotFound, ErrUserNotFound)
		}
		return errorResponse(c, http.StatusInternalServerError, err)
	}

	itemList := []*UserItem{}
	query = "SELECT * FROM user_items WHERE user_id = ?"
	if err = h.DB.Select(&itemList, query, userID); err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}

	cardList := make([]*UserCard, 0)
	query = "SELECT * FROM user_cards WHERE user_id=?"
	if err = h.DB.Select(&cardList, query, userID); err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}

	// genearte one time token
	query = "UPDATE user_one_time_tokens SET deleted_at=? WHERE user_id=? AND deleted_at IS NULL"
	if _, err = h.DB.Exec(query, requestAt, userID); err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}
	tID, err := h.generateID()
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}
	tk, err := generateUUID()
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}
	token := &UserOneTimeToken{
		ID:        tID,
		UserID:    userID,
		Token:     tk,
		TokenType: 2,
		CreatedAt: requestAt,
		UpdatedAt: requestAt,
		ExpiredAt: requestAt + 600,
	}
	query = "INSERT INTO user_one_time_tokens(id, user_id, token, token_type, created_at, updated_at, expired_at) VALUES (?, ?, ?, ?, ?, ?, ?)"
	if _, err = h.DB.Exec(query, token.ID, token.UserID, token.Token, token.TokenType, token.CreatedAt, token.UpdatedAt, token.ExpiredAt); err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}

	return successResponse(c, &ListItemResponse{
		OneTimeToken: token.Token,
		Items:        itemList,
		User:         user,
		Cards:        cardList,
	})
}

type ListItemResponse struct {
	OneTimeToken string      `json:"oneTimeToken"`
	User         *User       `json:"user"`
	Items        []*UserItem `json:"items"`
	Cards        []*UserCard `json:"cards"`
}

// addExpToCard 装備強化
// POST /user/{userID}/card/addexp/{cardID}
func (h *Handler) addExpToCard(c echo.Context) error {
	cardID, err := strconv.ParseInt(c.Param("cardID"), 10, 64)
	if err != nil {
		return errorResponse(c, http.StatusBadRequest, err)
	}

	userID, err := getUserID(c)
	if err != nil {
		return errorResponse(c, http.StatusBadRequest, err)
	}

	// read body
	defer c.Request().Body.Close()
	req := new(AddExpToCardRequest)
	if err := parseRequestBody(c, req); err != nil {
		return errorResponse(c, http.StatusBadRequest, err)
	}

	requestAt, err := getRequestTime(c)
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, ErrGetRequestTime)
	}

	if err = h.checkOneTimeToken(req.OneTimeToken, 2, requestAt); err != nil {
		if err == ErrInvalidToken {
			return errorResponse(c, http.StatusBadRequest, err)
		}
		return errorResponse(c, http.StatusInternalServerError, err)
	}

	if err = h.checkViewerID(userID, req.ViewerID); err != nil {
		if err == ErrUserDeviceNotFound {
			return errorResponse(c, http.StatusNotFound, err)
		}
		return errorResponse(c, http.StatusInternalServerError, err)
	}

	// get target card
	card := new(TargetUserCardData)
	query := `
	SELECT uc.id , uc.user_id , uc.card_id , uc.amount_per_sec , uc.level, uc.total_exp, im.amount_per_sec as 'base_amount_per_sec', im.max_level , im.max_amount_per_sec , im.base_exp_per_level
	FROM user_cards as uc
	INNER JOIN item_masters as im ON uc.card_id = im.id
	WHERE uc.id = ? AND uc.user_id=?
	`
	if err = h.DB.Get(card, query, cardID, userID); err != nil {
		if err == sql.ErrNoRows {
			return errorResponse(c, http.StatusNotFound, err)
		}
		return errorResponse(c, http.StatusInternalServerError, err)
	}

	if card.Level == card.MaxLevel {
		return errorResponse(c, http.StatusBadRequest, fmt.Errorf("target card is max level"))
	}

	// 消費アイテムの所持チェック
	items := make([]*ConsumeUserItemData, 0)
	query = `
	SELECT ui.id, ui.user_id, ui.item_id, ui.item_type, ui.amount, ui.created_at, ui.updated_at, im.gained_exp
	FROM user_items as ui
	INNER JOIN item_masters as im ON ui.item_id = im.id
	WHERE ui.item_type = 3 AND ui.id=? AND ui.user_id=?
	`
	for _, v := range req.Items {
		item := new(ConsumeUserItemData)
		// TODO: N+1
		if err = h.DB.Get(item, query, v.ID, userID); err != nil {
			if err == sql.ErrNoRows {
				return errorResponse(c, http.StatusNotFound, err)
			}
			return errorResponse(c, http.StatusInternalServerError, err)
		}

		if v.Amount > item.Amount {
			return errorResponse(c, http.StatusBadRequest, fmt.Errorf("item not enough"))
		}
		item.ConsumeAmount = v.Amount
		items = append(items, item)
	}

	// 経験値付与
	// 経験値をカードに付与
	for _, v := range items {
		card.TotalExp += v.GainedExp * v.ConsumeAmount
	}

	// lvup判定(lv upしたら生産性を加算)
	for {
		nextLvThreshold := int(float64(card.BaseExpPerLevel) * math.Pow(1.2, float64(card.Level-1)))
		if nextLvThreshold > card.TotalExp {
			break
		}

		// lv up処理
		card.Level += 1
		card.AmountPerSec += (card.MaxAmountPerSec - card.BaseAmountPerSec) / (card.MaxLevel - 1)
	}

	tx, err := h.DB.Beginx()
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}

	defer tx.Rollback() //nolint:errcheck

	// cardのlvと経験値の更新、itemの消費
	query = "UPDATE user_cards SET amount_per_sec=?, level=?, total_exp=?, updated_at=? WHERE id=?"
	if _, err = tx.Exec(query, card.AmountPerSec, card.Level, card.TotalExp, requestAt, card.ID); err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}

	query = "UPDATE user_items SET amount=?, updated_at=? WHERE id=?"
	for _, v := range items {
		// TODO: N+1
		if _, err = tx.Exec(query, v.Amount-v.ConsumeAmount, requestAt, v.ID); err != nil {
			return errorResponse(c, http.StatusInternalServerError, err)
		}
	}

	// get response data
	resultCard := new(UserCard)
	query = "SELECT * FROM user_cards WHERE id=?"
	if err = tx.Get(resultCard, query, card.ID); err != nil {
		if err == sql.ErrNoRows {
			return errorResponse(c, http.StatusNotFound, fmt.Errorf("not found card"))
		}
		return errorResponse(c, http.StatusInternalServerError, err)
	}
	resultItems := make([]*UserItem, 0)
	for _, v := range items {
		resultItems = append(resultItems, &UserItem{
			ID:        v.ID,
			UserID:    v.UserID,
			ItemID:    v.ItemID,
			ItemType:  v.ItemType,
			Amount:    v.Amount - v.ConsumeAmount,
			CreatedAt: v.CreatedAt,
			UpdatedAt: requestAt,
		})
	}

	err = tx.Commit()
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}

	return successResponse(c, &AddExpToCardResponse{
		UpdatedResources: makeUpdatedResources(requestAt, nil, nil, []*UserCard{resultCard}, nil, resultItems, nil, nil),
	})
}

type AddExpToCardRequest struct {
	ViewerID     string         `json:"viewerId"`
	OneTimeToken string         `json:"oneTimeToken"`
	Items        []*ConsumeItem `json:"items"`
}

type AddExpToCardResponse struct {
	UpdatedResources *UpdatedResource `json:"updatedResources"`
}

type ConsumeItem struct {
	ID     int64 `json:"id"`
	Amount int   `json:"amount"`
}

type ConsumeUserItemData struct {
	ID        int64 `db:"id"`
	UserID    int64 `db:"user_id"`
	ItemID    int64 `db:"item_id"`
	ItemType  int   `db:"item_type"`
	Amount    int   `db:"amount"`
	CreatedAt int64 `db:"created_at"`
	UpdatedAt int64 `db:"updated_at"`
	GainedExp int   `db:"gained_exp"`

	ConsumeAmount int // 消費量
}

type TargetUserCardData struct {
	ID           int64 `db:"id"`
	UserID       int64 `db:"user_id"`
	CardID       int64 `db:"card_id"`
	AmountPerSec int   `db:"amount_per_sec"`
	Level        int   `db:"level"`
	TotalExp     int   `db:"total_exp"`

	// lv1のときの生産性
	BaseAmountPerSec int `db:"base_amount_per_sec"`
	// 最高レベル
	MaxLevel int `db:"max_level"`
	// lv maxのときの生産性
	MaxAmountPerSec int `db:"max_amount_per_sec"`
	// lv1 -> lv2に上がるときのexp
	BaseExpPerLevel int `db:"base_exp_per_level"`
}

// updateDeck 装備変更
// POST /user/{userID}/card
func (h *Handler) updateDeck(c echo.Context) error {

	userID, err := getUserID(c)
	if err != nil {
		return errorResponse(c, http.StatusBadRequest, err)
	}

	// read body
	defer c.Request().Body.Close()
	req := new(UpdateDeckRequest)
	if err := parseRequestBody(c, req); err != nil {
		return errorResponse(c, http.StatusBadRequest, err)
	}

	if len(req.CardIDs) != DeckCardNumber {
		return errorResponse(c, http.StatusBadRequest, fmt.Errorf("invalid number of cards"))
	}

	requestAt, err := getRequestTime(c)
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, ErrGetRequestTime)
	}

	if err = h.checkViewerID(userID, req.ViewerID); err != nil {
		if err == ErrUserDeviceNotFound {
			return errorResponse(c, http.StatusNotFound, err)
		}
		return errorResponse(c, http.StatusInternalServerError, err)
	}

	// カード所持情報のバリデーション
	query := "SELECT * FROM user_cards WHERE id IN (?)"
	query, params, err := sqlx.In(query, req.CardIDs)
	if err != nil {
		return errorResponse(c, http.StatusBadRequest, err)
	}
	cards := make([]*UserCard, 0)
	if err = h.DB.Select(&cards, query, params...); err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}
	if len(cards) != DeckCardNumber {
		return errorResponse(c, http.StatusBadRequest, fmt.Errorf("invalid card ids"))
	}

	tx, err := h.DB.Beginx()
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}

	defer tx.Rollback() //nolint:errcheck

	// update data
	query = "UPDATE user_decks SET updated_at=?, deleted_at=? WHERE user_id=? AND deleted_at IS NULL"
	if _, err = tx.Exec(query, requestAt, requestAt, userID); err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}

	udID, err := h.generateID()
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}
	newDeck := &UserDeck{
		ID:        udID,
		UserID:    userID,
		CardID1:   req.CardIDs[0],
		CardID2:   req.CardIDs[1],
		CardID3:   req.CardIDs[2],
		CreatedAt: requestAt,
		UpdatedAt: requestAt,
	}
	query = "INSERT INTO user_decks(id, user_id, user_card_id_1, user_card_id_2, user_card_id_3, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)"
	if _, err := tx.Exec(query, newDeck.ID, newDeck.UserID, newDeck.CardID1, newDeck.CardID2, newDeck.CardID3, newDeck.CreatedAt, newDeck.UpdatedAt); err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}

	err = tx.Commit()
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}

	return successResponse(c, &UpdateDeckResponse{
		UpdatedResources: makeUpdatedResources(requestAt, nil, nil, nil, []*UserDeck{newDeck}, nil, nil, nil),
	})
}

type UpdateDeckRequest struct {
	ViewerID string  `json:"viewerId"`
	CardIDs  []int64 `json:"cardIds"`
}

type UpdateDeckResponse struct {
	UpdatedResources *UpdatedResource `json:"updatedResources"`
}

// reward ゲーム報酬受取
// POST /user/{userID}/reward
func (h *Handler) reward(c echo.Context) error {
	userID, err := getUserID(c)
	if err != nil {
		return errorResponse(c, http.StatusBadRequest, err)
	}

	// parse body
	defer c.Request().Body.Close()
	req := new(RewardRequest)
	if err := parseRequestBody(c, req); err != nil {
		return errorResponse(c, http.StatusBadRequest, err)
	}

	requestAt, err := getRequestTime(c)
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, ErrGetRequestTime)
	}

	if err = h.checkViewerID(userID, req.ViewerID); err != nil {
		if err == ErrUserDeviceNotFound {
			return errorResponse(c, http.StatusNotFound, err)
		}
		return errorResponse(c, http.StatusInternalServerError, err)
	}

	// 最後に取得した報酬時刻取得
	user := new(User)
	query := "SELECT * FROM users WHERE id=?"
	if err = h.DB.Get(user, query, userID); err != nil {
		if err == sql.ErrNoRows {
			return errorResponse(c, http.StatusNotFound, ErrUserNotFound)
		}
		return errorResponse(c, http.StatusInternalServerError, err)
	}

	// 使っているデッキの取得
	deck := new(UserDeck)
	query = "SELECT * FROM user_decks WHERE user_id=? AND deleted_at IS NULL"
	if err = h.DB.Get(deck, query, userID); err != nil {
		if err == sql.ErrNoRows {
			return errorResponse(c, http.StatusNotFound, err)
		}
		return errorResponse(c, http.StatusInternalServerError, err)
	}

	cards := make([]*UserCard, 0)
	query = "SELECT * FROM user_cards WHERE id IN (?, ?, ?)"
	if err = h.DB.Select(&cards, query, deck.CardID1, deck.CardID2, deck.CardID3); err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}
	if len(cards) != 3 {
		return errorResponse(c, http.StatusBadRequest, fmt.Errorf("invalid cards length"))
	}

	// 経過時間*生産性のcoin (1椅子 = 1coin)
	pastTime := requestAt - user.LastGetRewardAt
	getCoin := int(pastTime) * (cards[0].AmountPerSec + cards[1].AmountPerSec + cards[2].AmountPerSec)

	// 報酬の保存(ゲームない通貨を保存)(users)
	user.IsuCoin += int64(getCoin)
	user.LastGetRewardAt = requestAt

	query = "UPDATE users SET isu_coin=?, last_getreward_at=? WHERE id=?"
	if _, err = h.DB.Exec(query, user.IsuCoin, user.LastGetRewardAt, user.ID); err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}

	return successResponse(c, &RewardResponse{
		UpdatedResources: makeUpdatedResources(requestAt, user, nil, nil, nil, nil, nil, nil),
	})
}

type RewardRequest struct {
	ViewerID string `json:"viewerId"`
}

type RewardResponse struct {
	UpdatedResources *UpdatedResource `json:"updatedResources"`
}

// home ホーム取得
// GET /user/{userID}/home
func (h *Handler) home(c echo.Context) error {
	userID, err := getUserID(c)
	if err != nil {
		return errorResponse(c, http.StatusBadRequest, err)
	}

	requestAt, err := getRequestTime(c)
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, ErrGetRequestTime)
	}

	// 装備情報
	deck := new(UserDeck)
	query := "SELECT * FROM user_decks WHERE user_id=? AND deleted_at IS NULL"
	if err = h.DB.Get(deck, query, userID); err != nil {
		if err != sql.ErrNoRows {
			return errorResponse(c, http.StatusInternalServerError, err)
		}
		deck = nil
	}

	// 生産性
	cards := make([]*UserCard, 0)
	if deck != nil {
		cardIds := []int64{deck.CardID1, deck.CardID2, deck.CardID3}
		query, params, err := sqlx.In("SELECT * FROM user_cards WHERE id IN (?)", cardIds)
		if err != nil {
			return errorResponse(c, http.StatusInternalServerError, err)
		}
		if err = h.DB.Select(&cards, query, params...); err != nil {
			return errorResponse(c, http.StatusInternalServerError, err)
		}
	}
	totalAmountPerSec := 0
	for _, v := range cards {
		totalAmountPerSec += v.AmountPerSec
	}

	// 経過時間
	user := new(User)
	query = "SELECT * FROM users WHERE id=?"
	if err = h.DB.Get(user, query, userID); err != nil {
		if err == sql.ErrNoRows {
			return errorResponse(c, http.StatusNotFound, ErrUserNotFound)
		}
		return errorResponse(c, http.StatusInternalServerError, err)
	}
	pastTime := requestAt - user.LastGetRewardAt

	return successResponse(c, &HomeResponse{
		Now:               requestAt,
		User:              user,
		Deck:              deck,
		TotalAmountPerSec: totalAmountPerSec,
		PastTime:          pastTime,
	})
}

type HomeResponse struct {
	Now               int64     `json:"now"`
	User              *User     `json:"user"`
	Deck              *UserDeck `json:"deck,omitempty"`
	TotalAmountPerSec int       `json:"totalAmountPerSec"`
	PastTime          int64     `json:"pastTime"` // 経過時間を秒単位で
}

// //////////////////////////////////////
// util

// health ヘルスチェック
func (h *Handler) health(c echo.Context) error {
	return c.String(http.StatusOK, "OK")
}

// errorResponse returns error.
func errorResponse(c echo.Context, statusCode int, err error) error {
	c.Logger().Errorf("status=%d, err=%+v", statusCode, errors.WithStack(err))

	return c.JSON(statusCode, struct {
		StatusCode int    `json:"status_code"`
		Message    string `json:"message"`
	}{
		StatusCode: statusCode,
		Message:    err.Error(),
	})
}

// successResponse responds success.
func successResponse(c echo.Context, v interface{}) error {
	return c.JSON(http.StatusOK, v)
}

// noContentResponse
func noContentResponse(c echo.Context, status int) error {
	return c.NoContent(status)
}

// generateID uniqueなIDを生成する
func (h *Handler) generateID() (int64, error) {
	nextBase := atomic.AddInt64(&nextBaseID, 1)
	nextID := nextBase*10 + int64(serverNum)
	return nextID, nil
}

// generateSessionID
func generateUUID() (string, error) {
	id, err := uuid.NewRandom()
	if err != nil {
		return "", err
	}

	return id.String(), nil
}

// getUserID gets userID by path param.
func getUserID(c echo.Context) (int64, error) {
	return strconv.ParseInt(c.Param("userID"), 10, 64)
}

// getEnv gets environment variable.
func getEnv(key, defaultVal string) string {
	if v := os.Getenv(key); v == "" {
		return defaultVal
	} else {
		return v
	}
}

// parseRequestBody parses request body.
func parseRequestBody(c echo.Context, dist interface{}) error {
	buf, err := io.ReadAll(c.Request().Body)
	if err != nil {
		return ErrInvalidRequestBody
	}
	if err = json.Unmarshal(buf, &dist); err != nil {
		return ErrInvalidRequestBody
	}
	return nil
}

type UpdatedResource struct {
	Now  int64 `json:"now"`
	User *User `json:"user,omitempty"`

	UserDevice       *UserDevice       `json:"userDevice,omitempty"`
	UserCards        []*UserCard       `json:"userCards,omitempty"`
	UserDecks        []*UserDeck       `json:"userDecks,omitempty"`
	UserItems        []*UserItem       `json:"userItems,omitempty"`
	UserLoginBonuses []*UserLoginBonus `json:"userLoginBonuses,omitempty"`
	UserPresents     []*UserPresent    `json:"userPresents,omitempty"`
}

func makeUpdatedResources(
	requestAt int64,
	user *User,
	userDevice *UserDevice,
	userCards []*UserCard,
	userDecks []*UserDeck,
	userItems []*UserItem,
	userLoginBonuses []*UserLoginBonus,
	userPresents []*UserPresent,
) *UpdatedResource {
	return &UpdatedResource{
		Now:              requestAt,
		User:             user,
		UserDevice:       userDevice,
		UserCards:        userCards,
		UserItems:        userItems,
		UserDecks:        userDecks,
		UserLoginBonuses: userLoginBonuses,
		UserPresents:     userPresents,
	}
}

// //////////////////////////////////////
// entity

type User struct {
	ID              int64  `json:"id" db:"id"`
	IsuCoin         int64  `json:"isuCoin" db:"isu_coin"`
	LastGetRewardAt int64  `json:"lastGetRewardAt" db:"last_getreward_at"`
	LastActivatedAt int64  `json:"lastActivatedAt" db:"last_activated_at"`
	RegisteredAt    int64  `json:"registeredAt" db:"registered_at"`
	CreatedAt       int64  `json:"createdAt" db:"created_at"`
	UpdatedAt       int64  `json:"updatedAt" db:"updated_at"`
	DeletedAt       *int64 `json:"deletedAt,omitempty" db:"deleted_at"`
}

type UserDevice struct {
	ID           int64  `json:"id" db:"id"`
	UserID       int64  `json:"userId" db:"user_id"`
	PlatformID   string `json:"platformId" db:"platform_id"`
	PlatformType int    `json:"platformType" db:"platform_type"`
	CreatedAt    int64  `json:"createdAt" db:"created_at"`
	UpdatedAt    int64  `json:"updatedAt" db:"updated_at"`
	DeletedAt    *int64 `json:"deletedAt,omitempty" db:"deleted_at"`
}

type UserBan struct {
	ID        int64  `db:"id"`
	UserID    int64  `db:"user_id"`
	CreatedAt int64  `db:"created_at"`
	UpdatedAt int64  `db:"updated_at"`
	DeletedAt *int64 `db:"deleted_at"`
}

type UserCard struct {
	ID           int64  `json:"id" db:"id"`
	UserID       int64  `json:"userId" db:"user_id"`
	CardID       int64  `json:"cardId" db:"card_id"`
	AmountPerSec int    `json:"amountPerSec" db:"amount_per_sec"`
	Level        int    `json:"level" db:"level"`
	TotalExp     int64  `json:"totalExp" db:"total_exp"`
	CreatedAt    int64  `json:"createdAt" db:"created_at"`
	UpdatedAt    int64  `json:"updatedAt" db:"updated_at"`
	DeletedAt    *int64 `json:"deletedAt,omitempty" db:"deleted_at"`
}

type UserDeck struct {
	ID        int64  `json:"id" db:"id"`
	UserID    int64  `json:"userId" db:"user_id"`
	CardID1   int64  `json:"cardId1" db:"user_card_id_1"`
	CardID2   int64  `json:"cardId2" db:"user_card_id_2"`
	CardID3   int64  `json:"cardId3" db:"user_card_id_3"`
	CreatedAt int64  `json:"createdAt" db:"created_at"`
	UpdatedAt int64  `json:"updatedAt" db:"updated_at"`
	DeletedAt *int64 `json:"deletedAt,omitempty" db:"deleted_at"`
}

type UserItem struct {
	ID        int64  `json:"id" db:"id"`
	UserID    int64  `json:"userId" db:"user_id"`
	ItemType  int    `json:"itemType" db:"item_type"`
	ItemID    int64  `json:"itemId" db:"item_id"`
	Amount    int    `json:"amount" db:"amount"`
	CreatedAt int64  `json:"createdAt" db:"created_at"`
	UpdatedAt int64  `json:"updatedAt" db:"updated_at"`
	DeletedAt *int64 `json:"deletedAt,omitempty" db:"deleted_at"`
}

type UserLoginBonus struct {
	ID                 int64  `json:"id" db:"id"`
	UserID             int64  `json:"userId" db:"user_id"`
	LoginBonusID       int64  `json:"loginBonusId" db:"login_bonus_id"`
	LastRewardSequence int    `json:"lastRewardSequence" db:"last_reward_sequence"`
	LoopCount          int    `json:"loopCount" db:"loop_count"`
	CreatedAt          int64  `json:"createdAt" db:"created_at"`
	UpdatedAt          int64  `json:"updatedAt" db:"updated_at"`
	DeletedAt          *int64 `json:"deletedAt,omitempty" db:"deleted_at"`
}

type UserPresent struct {
	ID             int64  `json:"id" db:"id"`
	UserID         int64  `json:"userId" db:"user_id"`
	SentAt         int64  `json:"sentAt" db:"sent_at"`
	ItemType       int    `json:"itemType" db:"item_type"`
	ItemID         int64  `json:"itemId" db:"item_id"`
	Amount         int    `json:"amount" db:"amount"`
	PresentMessage string `json:"presentMessage" db:"present_message"`
	CreatedAt      int64  `json:"createdAt" db:"created_at"`
	UpdatedAt      int64  `json:"updatedAt" db:"updated_at"`
	DeletedAt      *int64 `json:"deletedAt,omitempty" db:"deleted_at"`
}

type UserPresentAllReceivedHistory struct {
	ID           int64  `json:"id" db:"id"`
	UserID       int64  `json:"userId" db:"user_id"`
	PresentAllID int64  `json:"presentAllId" db:"present_all_id"`
	ReceivedAt   int64  `json:"receivedAt" db:"received_at"`
	CreatedAt    int64  `json:"createdAt" db:"created_at"`
	UpdatedAt    int64  `json:"updatedAt" db:"updated_at"`
	DeletedAt    *int64 `json:"deletedAt,omitempty" db:"deleted_at"`
}

type Session struct {
	ID        int64  `json:"id" db:"id"`
	UserID    int64  `json:"userId" db:"user_id"`
	SessionID string `json:"sessionId" db:"session_id"`
	ExpiredAt int64  `json:"expiredAt" db:"expired_at"`
	CreatedAt int64  `json:"createdAt" db:"created_at"`
	UpdatedAt int64  `json:"updatedAt" db:"updated_at"`
	DeletedAt *int64 `json:"deletedAt,omitempty" db:"deleted_at"`
}

type UserOneTimeToken struct {
	ID        int64  `json:"id" db:"id"`
	UserID    int64  `json:"userId" db:"user_id"`
	Token     string `json:"token" db:"token"`
	TokenType int    `json:"tokenType" db:"token_type"`
	ExpiredAt int64  `json:"expiredAt" db:"expired_at"`
	CreatedAt int64  `json:"createdAt" db:"created_at"`
	UpdatedAt int64  `json:"updatedAt" db:"updated_at"`
	DeletedAt *int64 `json:"deletedAt,omitempty" db:"deleted_at"`
}

// //////////////////////////////////////
// master

type GachaMaster struct {
	ID           int64  `json:"id" db:"id"`
	Name         string `json:"name" db:"name"`
	StartAt      int64  `json:"startAt" db:"start_at"`
	EndAt        int64  `json:"endAt" db:"end_at"`
	DisplayOrder int    `json:"displayOrder" db:"display_order"`
	CreatedAt    int64  `json:"createdAt" db:"created_at"`
}

type GachaItemMaster struct {
	ID        int64 `json:"id" db:"id"`
	GachaID   int64 `json:"gachaId" db:"gacha_id"`
	ItemType  int   `json:"itemType" db:"item_type"`
	ItemID    int64 `json:"itemId" db:"item_id"`
	Amount    int   `json:"amount" db:"amount"`
	Weight    int   `json:"weight" db:"weight"`
	CreatedAt int64 `json:"createdAt" db:"created_at"`
}

type ItemMaster struct {
	ID              int64  `json:"id" db:"id"`
	ItemType        int    `json:"itemType" db:"item_type"`
	Name            string `json:"name" db:"name"`
	Description     string `json:"description" db:"description"`
	AmountPerSec    *int   `json:"amountPerSec" db:"amount_per_sec"`
	MaxLevel        *int   `json:"maxLevel" db:"max_level"`
	MaxAmountPerSec *int   `json:"maxAmountPerSec" db:"max_amount_per_sec"`
	BaseExpPerLevel *int   `json:"baseExpPerLevel" db:"base_exp_per_level"`
	GainedExp       *int   `json:"gainedExp" db:"gained_exp"`
	ShorteningMin   *int64 `json:"shorteningMin" db:"shortening_min"`
	// CreatedAt       int64 `json:"createdAt"`
}

type LoginBonusMaster struct {
	ID          int64 `json:"id" db:"id"`
	StartAt     int64 `json:"startAt" db:"start_at"`
	EndAt       int64 `json:"endAt" db:"end_at"`
	ColumnCount int   `json:"columnCount" db:"column_count"`
	Looped      bool  `json:"looped" db:"looped"`
	CreatedAt   int64 `json:"createdAt" db:"created_at"`
}

type LoginBonusRewardMaster struct {
	ID             int64 `json:"id" db:"id"`
	LoginBonusID   int64 `json:"loginBonusId" db:"login_bonus_id"`
	RewardSequence int   `json:"rewardSequence" db:"reward_sequence"`
	ItemType       int   `json:"itemType" db:"item_type"`
	ItemID         int64 `json:"itemId" db:"item_id"`
	Amount         int64 `json:"amount" db:"amount"`
	CreatedAt      int64 `json:"createdAt" db:"created_at"`
}

type PresentAllMaster struct {
	ID                int64  `json:"id" db:"id"`
	RegisteredStartAt int64  `json:"registeredStartAt" db:"registered_start_at"`
	RegisteredEndAt   int64  `json:"registeredEndAt" db:"registered_end_at"`
	ItemType          int    `json:"itemType" db:"item_type"`
	ItemID            int64  `json:"itemId" db:"item_id"`
	Amount            int64  `json:"amount" db:"amount"`
	PresentMessage    string `json:"presentMessage" db:"present_message"`
	CreatedAt         int64  `json:"createdAt" db:"created_at"`
}

type VersionMaster struct {
	ID            int64  `json:"id" db:"id"`
	Status        int    `json:"status" db:"status"`
	MasterVersion string `json:"masterVersion" db:"master_version"`
}
