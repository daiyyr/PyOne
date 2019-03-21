var need_refresh=true;
function ShowNotice(msg){
    mdui.snackbar({
          message: msg,
          position: 'top'
        });
}

function reserveCheck(name) {
    var revalue = document.getElementsByName(name);
    for (i = 0; i < revalue.length; i++) {
        if (revalue[i].checked == true){
            revalue[i].checked = false;
            need_refresh=true;
        }
        else {
            revalue[i].checked = true;
            need_refresh=false;
        }
    }
}

function SelectGid(){
    need_refresh=!need_refresh;
}


function DoAction(action,gid){
    var defer = $.Deferred();
    $.ajax({
        type: "POST",
        url: "/admin/jsonrpc",
        data: { action:action,gid:gid },
        cache: false, //使用同步的方式,true为异步方式
        dataType: "json",
        success: function(data) {
            defer.resolve(data);
            ShowNotice(data['result'][0]['msg']);
            defer.promise();
        }
    });
}
function pause(gid){
    var defer = $.Deferred();
    $.ajax({
        type: "POST",
        url: "/admin/jsonrpc",
        data: { action:'pause',gid:gid },
        cache: false, //使用同步的方式,true为异步方式
        dataType: "json",
        success: function(data) {
            defer.resolve(data);
            ShowNotice(data['result'][0]['msg']);
            defer.promise();
        }
    });
}
function unpause(gid){
    var defer = $.Deferred();
    $.ajax({
        type: "POST",
        url: "/admin/jsonrpc",
        data: { action:'unpause',gid:gid },
        cache: false, //使用同步的方式,true为异步方式
        dataType: "json",
        success: function(data) {
            defer.resolve(data);
            ShowNotice(data['result'][0]['msg']);
            defer.promise();
        }
    });
}
function remove(gid){
    var defer = $.Deferred();
    $.ajax({
        type: "POST",
        url: "/admin/jsonrpc",
        data: { action:'remove',gid:gid },
        cache: false, //使用同步的方式,true为异步方式
        dataType: "json",
        success: function(data) {
            defer.resolve(data);
            ShowNotice(data['result'][0]['msg']);
            defer.promise();
        }
    });
}
function removeAll(gid){
    var defer = $.Deferred();
    $.ajax({
        type: "POST",
        url: "/admin/jsonrpc",
        data: { action:'removeAll',gid:gid },
        cache: false, //使用同步的方式,true为异步方式
        dataType: "json",
        success: function(data) {
            defer.resolve(data);
            ShowNotice(data['result'][0]['msg']);
            defer.promise();
        }
    });
}
function restart(gid){
    var defer = $.Deferred();
    $.ajax({
        type: "POST",
        url: "/admin/jsonrpc",
        data: { action:'restart',gid:gid },
        cache: false, //使用同步的方式,true为异步方式
        dataType: "json",
        success: function(data) {
            defer.resolve(data);
            ShowNotice(data['result'][0]['msg']);
            defer.promise();
        }
    });
}
function selected(gid){
    var defer = $.Deferred();
    $.ajax({
        type: "POST",
        url: "/admin/jsonrpc",
        data: { action:'selected',gid:gid },
        cache: false, //使用同步的方式,true为异步方式
        dataType: "json",
        success: function(data) {
            defer.resolve(data);
            ShowNotice(data['result'][0]['msg']);
            defer.promise();
        }
    });
}
function unselected(gid){
    var defer = $.Deferred();
    $.ajax({
        type: "POST",
        url: "/admin/jsonrpc",
        data: { action:'unselected',gid:gid },
        cache: false, //使用同步的方式,true为异步方式
        dataType: "json",
        success: function(data) {
            defer.resolve(data);
            ShowNotice(data['result'][0]['msg']);
            defer.promise();
        }
    });
}


function ClearHist(){
    layer.confirm('确定清除任务？', {
        btn: ['确定','取消'] //按钮
    },
    function(index){
        layer.close(index);
        $.ajax({
            type: "POST",
            url: "/admin/clearHist",
            dataType: "json",
            beforeSend: function(xhr) {
                var index2 = layer.load(2, {
                    shade: [0.1, '#fff'] //0.1透明度的白色背景
                });
            },
            success: function(data) {
                ShowNotice(data.msg);
            },
            complete: function(xhr) {
                $('#layui-layer-shade1').remove();
                setTimeout("window.location.reload();",2000);
            }
        });
        }
    );
}

function tellActive() {
    var defer = $.Deferred();
    var getTimestamp=new Date().getTime();
    $.ajax({
        type: "POST",
        url: "/admin/jsonrpc?t="+getTimestamp,
        data: { action:'tellActive' },
        cache: false, //使用同步的方式,true为异步方式
        // async: false, //使用同步的方式,true为异步方式
        dataType: "json",
        success: function(data) {
            defer.resolve(data);
            if(!need_refresh){
                return
            }
            if (data.code==1) {
                $('#active').empty();
                for (var i = data.result.length - 1; i >= 0; i--) {
                    t=data.result[i];
                    html='  <div class="mdui-panel-item" onclick="SelectGid();">';
                    //header
                    html+='   <div class="mdui-panel-item-header">';
                    html+='        <div class="mdui-col-xs-6 mdui-text-truncate">'+t['title']+'</div>';
                    html+='        <div class="mdui-col-xs-4">'+t['size']+' / '+t['down_percent']+' / '+t['speed']+'</div>';
                         //active -- >pause/unpause/remove
                        td='       <div class="mdui-col-xs-2">&nbsp;&nbsp;&nbsp;';
                        if(t['down_status']=='暂停下载'){
                            td+='<button class="mdui-btn mdui-btn-icon" onclick="unpause(\''+t['gid']+'\')" mdui-tooltip="{content: \'开始任务\'}"><i class="mdui-icon material-icons">&#xe037;</i></button> ';
                        }
                        else{
                            td+='<button class="mdui-btn mdui-btn-icon" onclick="pause(\''+t['gid']+'\')" mdui-tooltip="{content: \'暂停任务\'}"><i class="mdui-icon material-icons">&#xe047;</i></button> ';
                        }
                        // if(t['selectable']=='true'){
                        //     td+='<button class="mdui-btn mdui-btn-icon" onclick="unselected(\''+t['gid']+'#'+t['idx']+'\')" mdui-tooltip="{content: \'选择不下载文件\'}"><i class="mdui-icon material-icons">&#xe5c9;</i></button>';
                        // }
                        // td+='<button class="mdui-btn mdui-btn-icon" onclick="remove(\''+t['gid']+'#'+t['idx']+'\')" mdui-tooltip="{content: \'删除任务\'}"><i class="mdui-icon material-icons">&#xe872;</i></button>';
                        td+='<button class="mdui-btn mdui-btn-icon" onclick="removeAll(\''+t['gid']+'\')" mdui-tooltip="{content: \'删除同磁力下所有任务\'}"><i class="mdui-icon material-icons">&#xe92b;</i></button>';
                        td+='<button class="mdui-btn mdui-btn-icon" onclick="restart(\''+t['gid']+'\')" mdui-tooltip="{content: \'重新开始\'}"><i class="mdui-icon material-icons">&#xe863;</i></button> ';
                        td+='      </div>';
                        html+=td;
                        //active end
                    html+='    </div>';
                    //header end
                    //内嵌页面
                    html+='    <div class="mdui-panel-item-body">';
                    html+='       <ul class="mdui-list mdui-color-blue-50 mdui-typo-caption">'
                        // subtitle
                        html+='<li class="mdui-list-item mdui-ripple">';
                        html+='<div class="mdui-col-xs-8 mdui-col-offset-xs-1">文件名</div>';
                        html+='<div class="mdui-col-xs-1 ">大小</div>';
                        html+='<div class="mdui-col-xs-1 ">下载</div>';
                        html+='<div class="mdui-col-xs-1 ">上传</div>';
                        html+='<div class="mdui-col-xs-1 ">操作</div>';
                        html+='</li>';
                        // subtitle end
                        for (var j = 0; j <= t.files.length - 1; j++) {
                            file=t.files[j];
                            inner_html='<li class="mdui-list-item mdui-ripple">';
                            inner_html+='<div class="mdui-col-xs-8 mdui-col-offset-xs-1 mdui-typo-body-1">'+file['name']+'</div>';
                            inner_html+='<div class="mdui-col-xs-1 ">'+file['size']+'</div>';
                            inner_html+='<div class="mdui-col-xs-1 ">'+file['down_status']+'</div>';
                            inner_html+='<div class="mdui-col-xs-1 ">'+file['up_status']+'</div>';
                                //sub操作
                                inner_html+='<div class="mdui-col-xs-1 ">';
                                if(file['selected']=='true'){
                                    inner_html+='<button class="mdui-btn mdui-btn-icon" onclick="unselected(\''+t['gid']+'#'+file['idx']+'\')" mdui-tooltip="{content: \'选择不下载文件\'}"><i class="mdui-icon material-icons">&#xe834;</i></button>';
                                }
                                else{
                                    inner_html+='<button class="mdui-btn mdui-btn-icon" onclick="selected(\''+t['gid']+'#'+file['idx']+'\')" mdui-tooltip="{content: \'选择下载文件\'}"><i class="mdui-icon material-icons">&#xe835;</i></button>';
                                }
                                inner_html+='</div>';
                                //sub操作 end
                            inner_html+='</li>'
                            html+=inner_html;
                        }
                    html+='       </ul>';
                    html+='    </div>';
                    //内嵌结束
                    html+='  </div>';
                    $('#active').append(html);
                }
            } else {
                ShowNotice(data.msg);
            }
        },
        complete:function(){
            defer.promise();
            tellFail();
        }
    });
}

function tellFail() {
    var defer = $.Deferred();
    var getTimestamp=new Date().getTime();
    $.ajax({
        type: "POST",
        url: "/admin/jsonrpc?t="+getTimestamp,
        data: { action:'tellFail' },
        cache: false, //使用同步的方式,true为异步方式
        // async: false, //使用同步的方式,true为异步方式
        dataType: "json",
        success: function(data) {
            defer.resolve(data);
            if(!need_refresh){
                return
            }
            if (data.code==1) {
                $('#fail').empty();
                for (var i = 0; i <= data.result.length - 1; i++) {
                    t=data.result[i];
                    html='  <div class="mdui-panel-item" onclick="SelectGid();">';
                    //header
                    html+='   <div class="mdui-panel-item-header">';
                    html+='        <div class="mdui-col-xs-6 mdui-text-truncate">'+t['title']+'</div>';
                    html+='        <div class="mdui-col-xs-4">'+t['size']+' / '+t['down_percent']+' / '+t['speed']+'</div>';
                         //active -- >pause/unpause/remove
                        td='       <div class="mdui-col-xs-2">&nbsp;&nbsp;&nbsp;';
                        if(t['down_status']=='暂停下载'){
                            td+='<button class="mdui-btn mdui-btn-icon" onclick="unpause(\''+t['gid']+'\')" mdui-tooltip="{content: \'开始任务\'}"><i class="mdui-icon material-icons">&#xe037;</i></button> ';
                        }
                        else{
                            td+='<button class="mdui-btn mdui-btn-icon" onclick="pause(\''+t['gid']+'\')" mdui-tooltip="{content: \'暂停任务\'}"><i class="mdui-icon material-icons">&#xe047;</i></button> ';
                        }
                        // if(t['selectable']=='true'){
                        //     td+='<button class="mdui-btn mdui-btn-icon" onclick="unselected(\''+t['gid']+'#'+t['idx']+'\')" mdui-tooltip="{content: \'选择不下载文件\'}"><i class="mdui-icon material-icons">&#xe5c9;</i></button>';
                        // }
                        // td+='<button class="mdui-btn mdui-btn-icon" onclick="remove(\''+t['gid']+'#'+t['idx']+'\')" mdui-tooltip="{content: \'删除任务\'}"><i class="mdui-icon material-icons">&#xe872;</i></button>';
                        td+='<button class="mdui-btn mdui-btn-icon" onclick="removeAll(\''+t['gid']+'\')" mdui-tooltip="{content: \'删除同磁力下所有任务\'}"><i class="mdui-icon material-icons">&#xe92b;</i></button>';
                        td+='<button class="mdui-btn mdui-btn-icon" onclick="restart(\''+t['gid']+'\')" mdui-tooltip="{content: \'重新开始\'}"><i class="mdui-icon material-icons">&#xe863;</i></button> ';
                        td+='      </div>';
                        //active end
                    html+=td;
                    html+='    </div>';
                    //header end
                    //内嵌页面
                    html+='    <div class="mdui-panel-item-body">';
                    html+='       <ul class="mdui-list mdui-color-blue-50 mdui-typo-caption">'
                        // subtitle
                        html+='<li class="mdui-list-item mdui-ripple">';
                        html+='<div class="mdui-col-xs-8 mdui-col-offset-xs-1">文件名</div>';
                        html+='<div class="mdui-col-xs-1 ">大小</div>';
                        html+='<div class="mdui-col-xs-1 ">下载</div>';
                        html+='<div class="mdui-col-xs-1 ">上传</div>';
                        html+='<div class="mdui-col-xs-1 ">操作</div>';
                        html+='</li>';
                        // subtitle end
                        for (var j = 0; j <= t.files.length - 1; j++) {
                            file=t.files[j];
                            inner_html='<li class="mdui-list-item mdui-ripple">';
                            inner_html+='<div class="mdui-col-xs-8 mdui-col-offset-xs-1 mdui-typo-body-1">'+file['name']+'</div>';
                            inner_html+='<div class="mdui-col-xs-1 ">'+file['size']+'</div>';
                            inner_html+='<div class="mdui-col-xs-1 ">'+file['down_status']+'</div>';
                            inner_html+='<div class="mdui-col-xs-1 ">'+file['up_status']+'</div>';
                                //sub操作
                                inner_html+='<div class="mdui-col-xs-1 ">';
                                if(file['selected']=='true'){
                                    inner_html+='<button class="mdui-btn mdui-btn-icon" onclick="unselected(\''+t['gid']+'#'+file['idx']+'\')" mdui-tooltip="{content: \'选择不下载文件\'}"><i class="mdui-icon material-icons">&#xe834;</i></button>';
                                }
                                else{
                                    inner_html+='<button class="mdui-btn mdui-btn-icon" onclick="selected(\''+t['gid']+'#'+file['idx']+'\')" mdui-tooltip="{content: \'选择下载文件\'}"><i class="mdui-icon material-icons">&#xe835;</i></button>';
                                }
                                inner_html+='</div>';
                                //sub操作 end
                            inner_html+='</li>'
                            html+=inner_html;
                        }
                    html+='       </ul>';
                    html+='    </div>';
                    //内嵌结束
                    html+='  </div>';
                    $('#fail').append(html);
                }
            } else {
                ShowNotice(data.msg);
            }
        },
        complete:function(){
            defer.promise();
            tellSuccess();
        }
    });
}

function tellSuccess() {
    var defer = $.Deferred();
    var getTimestamp=new Date().getTime();
    $.ajax({
        type: "POST",
        url: "/admin/jsonrpc?t="+getTimestamp,
        data: { action:'tellSuccess' },
        cache: false,
        // async: false,
        dataType: "json",
        success: function(data) {
             defer.resolve(data);
             if(!need_refresh){
                return
            }
            $('#success').empty();
            if (data.code==1) {
                for (var i = 0; i <= data.result.length - 1; i++) {
                    t=data.result[i];
                    html='  <div class="mdui-panel-item" onclick="SelectGid();">';
                    //header
                    html+='   <div class="mdui-panel-item-header">';
                    html+='        <div class="mdui-col-xs-6 mdui-text-truncate">'+t['title']+'</div>';
                    html+='        <div class="mdui-col-xs-4">'+t['size']+' / '+t['down_percent']+' / '+t['speed']+'</div>';
                         //active -- >pause/unpause/remove
                        td='       <div class="mdui-col-xs-2">&nbsp;&nbsp;&nbsp;';
                        // if(t['selectable']=='true'){
                        //     td+='<button class="mdui-btn mdui-btn-icon" onclick="unselected(\''+t['gid']+'#'+t['idx']+'\')" mdui-tooltip="{content: \'选择不下载文件\'}"><i class="mdui-icon material-icons">&#xe5c9;</i></button>';
                        // }
                        // td+='<button class="mdui-btn mdui-btn-icon" onclick="remove(\''+t['gid']+'#'+t['idx']+'\')" mdui-tooltip="{content: \'删除任务\'}"><i class="mdui-icon material-icons">&#xe872;</i></button>';
                        td+='<button class="mdui-btn mdui-btn-icon" onclick="removeAll(\''+t['gid']+'\')" mdui-tooltip="{content: \'删除同磁力下所有任务\'}"><i class="mdui-icon material-icons">&#xe92b;</i></button>';
                        td+='<button class="mdui-btn mdui-btn-icon" onclick="restart(\''+t['gid']+'\')" mdui-tooltip="{content: \'重新开始\'}"><i class="mdui-icon material-icons">&#xe863;</i></button> ';
                        td+='      </div>';
                        html+=td;
                        //active end
                    html+='    </div>';
                    //header end
                    //内嵌页面
                    html+='    <div class="mdui-panel-item-body">';
                    html+='       <ul class="mdui-list mdui-color-blue-50 mdui-typo-caption">'
                        // subtitle
                        html+='<li class="mdui-list-item mdui-ripple">';
                        html+='<div class="mdui-col-xs-8 mdui-col-offset-xs-1">文件名</div>';
                        html+='<div class="mdui-col-xs-1 ">大小</div>';
                        html+='<div class="mdui-col-xs-1 ">下载</div>';
                        html+='<div class="mdui-col-xs-1 ">上传</div>';
                        html+='<div class="mdui-col-xs-1 ">操作</div>';
                        html+='</li>';
                        // subtitle end
                        for (var j = 0; j <= t.files.length - 1; j++) {
                            file=t.files[j];
                            inner_html='<li class="mdui-list-item mdui-ripple">';
                            inner_html+='<div class="mdui-col-xs-8 mdui-col-offset-xs-1 mdui-typo-body-1">'+file['name']+'</div>';
                            inner_html+='<div class="mdui-col-xs-1 ">'+file['size']+'</div>';
                            inner_html+='<div class="mdui-col-xs-1 ">'+file['down_status']+'</div>';
                            inner_html+='<div class="mdui-col-xs-1 ">'+file['up_status']+'</div>';
                                //sub操作
                                inner_html+='<div class="mdui-col-xs-1 ">';
                                inner_html+='</div>';
                                //sub操作 end
                            inner_html+='</li>'
                            html+=inner_html;
                        }
                    html+='       </ul>';
                    html+='    </div>';
                    //内嵌结束
                    html+='  </div>';
                    $('#success').append(html);
                }
            } else {
                ShowNotice(data.msg);
            }
        },
        complete: function(){
            defer.promise();
            // tellUnselected();
        }
    });
}
function Refresh(){
    tellActive();
}
var interval_id=null;
function AutoRefresh(){
    if (interval_id){
        window.clearInterval(interval_id);
    }
    interval_id = window.setInterval(function(){
        if(need_refresh){
            Refresh();
        }
    },2000);
}
AutoRefresh();
